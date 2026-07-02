---
repo: darwin-net
schema: phases/v1
current_phase: M5
updated: 2026-07-02
updated_by: roadmap/m7-m9

phases:
  - id: M0
    title: Walking skeleton (no darwin-net work — single node, node IP only)
    status: done
    completed: 2026-06-24
    depends_on: []
    subphases: []

  - id: M1
    title: Services + DNS (single node) — userspace Service proxy + CoreDNS + getaddrinfo shim
    status: done
    completed: 2026-06-25
    depends_on:
      - apis:M1.2
    subphases:
      - id: M1.1
        title: Userspace Service proxy (ClusterIP)
        status: done
        deliverables:
          - id: M1.1-d1
            done: true
            desc: pkg/proxy — userspace Service proxy owning each ClusterIP:port on an lo0 alias, watching Services/EndpointSlices, L4 load-balancing to local backends (NodePort binds *:port)
        acceptance:
          - id: M1.1-a1
            met: true
            check: a ClusterIP VIP load-balances across backend endpoints in a faked watch; the routing table is pure-logic table-tested
            method: unit
          - id: M1.1-a2
            met: true
            check: lo0 alias create/teardown is idempotent and leak-free under churn (root-gated integration; rootless path binds 127/8)
            method: integration
      - id: M1.2
        title: CoreDNS wiring + getaddrinfo shim
        status: done
        deliverables:
          - id: M1.2-d1
            done: true
            desc: pkg/dns — wire CoreDNS as the cluster resolver on a VIP plus a DYLD_INSERT_LIBRARIES getaddrinfo/res_* shim routing pod name resolution to CoreDNS (not resolv.conf — macOS uses mDNSResponder)
        acceptance:
          - id: M1.2-a1
            met: true
            check: a pod process with the shim resolves a Service name via CoreDNS; without the shim it does not
            method: integration

  - id: M2
    title: IP-per-pod (lo0 alias IPAM + bind discipline) + PodNetwork seam + in-pod API resolution
    status: done
    completed: 2026-06-25
    depends_on:
      - apis:M2.1
    subphases:
      - id: M2.1
        title: IP-per-pod lo0 alias IPAM + the PodNetwork seam
        status: done
        completed: 2026-06-25
        deliverables:
          - id: M2.1-d1
            done: true
            desc: "`ifconfig lo0 alias <ip>/32` IPAM out of the node's podCIDR (per-node /24 from 100.64.0.0/10) + the PodNetwork interface runtimed calls during pod setup (allocate IP, plumb lo0 alias, return the IP to bind). Pairs with runtimed:M2 (runtimed binds the process to the returned IP via IP_BOUND_IF). pkg/podnet: Allocator (pure IPAM core — per-node /24 carve via NodeCIDR, unique /32 allocate/release, leak-tracking), aliasManager seam (real `ifconfig lo0 alias` + rootless fake, mirroring pkg/proxy), Network implementing PodNetwork (Setup: allocate→ensure alias→return bindable IP, idempotent per pod, rolls back on alias failure; Teardown: remove alias→release, leak-free). The returned IP flows into the existing runtime/v1 PodBox.pod_ip (no apis change). The `pf` k3sm sub-anchor is deferred to M4 (root netd boundary)."
        acceptance:
          - id: M2.1-a1
            met: true
            check: IPAM allocate/release is leak-free and idempotent under churn (pure-logic table test); the per-node /24 carve is collision-free and stable across restart
            method: unit
          - id: M2.1-a2
            met: true
            check: PodNetwork.Setup plumbs the lo0 alias and returns the bindable IP; teardown removes it; root-gated integration on a capable host
            method: integration
      - id: M2.2
        title: In-pod resolution of kubernetes.default.svc under the confined runtime
        status: done
        completed: 2026-06-25
        deliverables:
          - id: M2.2-d1
            done: true
            desc: "Make in-pod DNS resolution of `kubernetes.default.svc` (and cluster names generally) work under Seatbelt confinement. Apple's `sandbox-exec` strips `DYLD_*` from the child env, so the M1 `DYLD_INSERT_LIBRARIES` getaddrinfo shim only loads under runtimed's NON-PLATFORM exec-shim backend. Pin that backend for the in-pod-API resolution path (coordinate with runtimed:M2), OR document + implement the machine-wide DNS-proxy alternative (mDNSResponder resolver scoped to the cluster domain) for the platform/confined backend. Mostly a constraint + verification — likely no new darwin-net code beyond the backend pin and a documented decision. OUTCOME: reduced to verification + doc. `kubernetes.default.svc` needs no special-casing — the M1 resolver's ndots/search candidate expansion resolves it (partial form -> kubernetes.default.svc.cluster.local) and cross-namespace `<svc>.<ns>` -> `<svc>.<ns>.svc.cluster.local`, while bare names stay in-namespace (the k8s contract). No new darwin-net code; the in-pod-API path is documented (pkg/dns/doc.go) to REQUIRE runtimed's non-platform exec-shim backend (the chosen mitigation: backend pin, coordinate runtimed:M2), with the machine-wide DNS proxy named as the future platform-backend alternative."
        acceptance:
          - id: M2.2-a1
            met: true
            check: a pod launched under the exec-shim backend resolves kubernetes.default.svc via CoreDNS; the platform/confined-backend limitation (DYLD_* stripped) is documented with the chosen mitigation (backend pin or DNS proxy)
            method: integration

  - id: M3
    title: wireguard-go mesh over utun + MeshPeer consumption + NodePort + infra-VIP mesh exemption
    status: done
    completed: 2026-06-25
    depends_on:
      - apis:M3.2
    subphases:
      - id: M3.1
        title: wireguard-go mesh over utun + MeshPeer consumption
        status: done
        completed: 2026-06-25
        deliverables:
          - id: M3.1-d1
            done: true
            desc: "`pkg/mesh` over a root-created utun via wireguard-go (pinned pseudo-version; CGO_ENABLED=0). Consumes the net.k3sm.io/v1 MeshPeer CRD (apis): AllowedIPs per peer = its podCIDR, SYMMETRIC, and the mesh asserts AllowedIPs == podnet IPAM CIDR == node.spec.podCIDR (equality, not just symmetry). Load-bearing mechanics from the M3 re-plan, each table-tested as pure logic with the privileged ops behind the Device seam (netd/root boundary): (1) PER-PEER KERNEL ROUTES (`route add -net <peer/24> -interface utun`) computed by RouteSet as a step DISTINCT from wg AllowedIPs (wireguard-go over a raw utun installs no routes like wg-quick) — RouteSet NEVER includes this node's own /24 or the 100.64.0.0/10 aggregate (loopback theft); (2) a RESERVED mesh-egress /32 (podnet.MeshEgressIP = the node /24's .1) EXCLUDED from the podnet allocator (which used to hand .1 as the first pod IP — fixed; first pod IP is now .2) and bound as the Service-proxy backend dialer's LocalAddr (proxy.WithMeshEgressSource) so cross-node return packets are accepted by peers' AllowedIPs; (3) WATCH the MeshPeer CRD (netv1.AddToScheme typed informer) and reconcile endpoint/key changes continuously (not a one-shot read) via a full-resync UAPI; (4) MTU 1380 + PersistentKeepalive 25 (apis constants); (5) a MINIMAL pf scrub anchor pulled forward from M4 clamping max-mss=1340 SCOPED to the utun egress (never lo0). No relay (mutually-routable/same-L2 endpoints). Private keys never leave the node (never on a MeshPeer)."
        acceptance:
          - id: M3.1-a1
            met: true
            check: "pure-logic mechanics proven by named unit tests (no root): TestMeshRoutesPerPeerNotAggregate (route set = one /24 per peer; own /24 and /10 aggregate NEVER present), TestMeshEgressSourceReserved (the mesh /32 is derived from the podCIDR AND excluded from the allocator — first pod IP is .2), TestMeshAllowedIPsEqualsCIDR (AllowedIPs == IPAM CIDR == podCIDR per peer; symmetric-but-wrong rejected), TestMeshReconcileEndpointChange (an endpoint change is reconciled, not ignored). The real utun/route/pf bring-up is the wired root-gated integration test TestMeshDeviceBringUpOnRealUTUN (//go:build integration, t.Skip without root). The full two-real-Macs reachability (iperf3 both directions) + bounce-a-node→reconverge is the K3SM_LAB=1 two-Mac gate."
            method: unit+integration
      - id: M3.2
        title: NodePort in the userspace Service proxy (TCP)
        status: done
        completed: 2026-06-25
        deliverables:
          - id: M3.2-d1
            done: true
            desc: "NodePort Services in the userspace Service proxy: a non-zero ServicePort.NodePort opens a node-wide `*:nodePort` (wildcard) TCP listener alongside the ClusterIP listener, L4-LB to the SAME ready endpoints, reusing the M1 RoutingTable (already protocol-keyed). The path existed since M1; M3.2 makes it the explicit, documented NodePort path (proxy.openListener + doc.go `# NodePort`). externalTrafficPolicy: Cluster ONLY — the userspace splice opens a fresh backend connection and so does NOT preserve the client source IP, so externalTrafficPolicy: Local is NOT honored (documented). No apis change — `ServicePort.NodePort` already exists (apis:M3.1-d3 pins it unchanged). UDP NodePort is DEFERRED with the UDP datagram relay + idle-flow GC (a UDP port opens NO datagram socket on either the ClusterIP or the NodePort); stockkitty's NodePort surface (VSCode SSH :22, snapshot gRPC range) is all TCP, so UDP NodePort is NOT claimed until the relay lands."
        acceptance:
          - id: M3.2-a1
            met: true
            check: "the NodePort path is proven by the named pure-logic/faked unit test (no root): TestNodePortBindsWildcard — a TCP NodePort Service yields a `*:nodePort` wildcard listener that load-balances across ready backends (dialed via loopback), and a UDP NodePort opens NO listener (relay deferred → not claimed); the externalTrafficPolicy: Cluster semantics (no client-source-IP preservation through the L4 splice) are documented in pkg/proxy/doc.go + openListener. The live external-client reachability on a real `*:nodePort` is the root-gated/lab integration leg."
            method: unit+integration
      - id: M3.3
        title: Infra-VIP exemption from podCIDR mesh steering (multi-node correctness)
        status: done
        completed: 2026-06-25
        depends_on:
          - apis:M3.2
          - k3sm:M3.3
        deliverables:
          - id: M3.3-d1
            done: true
            desc: "Keep the infra VIPs — the `kubernetes` ClusterIP (10.43.0.1) and the kube-dns VIP (10.43.0.10) — node-local so they are never steered over the wireguard mesh (no peer's symmetric AllowedIPs = podCIDR covers them → a mesh-steered infra VIP blackholes in-pod kubectl + DNS on multi-node). darwin-net's half: (1) PER-NODE CoreDNS bound to the DNS VIP — pkg/dns.PerNodeDNS renders a Corefile with `bind <DefaultDNSVIP=10.43.0.10>` on :53, so every node answers cluster DNS over loopback, never the mesh; (2) the kube-dns VIP EXEMPTION from proxy ownership for BOTH 53/TCP and 53/UDP — proxy.WithInfraVIPExemptions registers the VIP and Proxy.Reconcile steps aside (no worker, no lo0 alias, no listener, no routing entry) so CoreDNS (which binds 10.43.0.10:53 directly) never hits EADDRINUSE (the M1 UDP path only dodged the collision by accident; TCP had no exemption). Locality STAYS A HINT: classify() is NOT made load-bearing for steering (it mislabels loopback/node-local as remote) — infra VIPs stay off the utun because the mesh installs kernel routes for peer pod /24s ONLY (M3.1 RouteSet), never the 10.43/16 infra range. The `kubernetes` 10.43.0.1 endpoint rewrite to a node-local apiserver/proxy address is k3sm-owned (k3sm:M3.3, the depends_on edge); darwin-net provides the per-node CoreDNS + the exemption seam, and k3sm ensures the 10.43.0.10/32 lo0 alias for its per-node CoreDNS (root/netd boundary)."
        acceptance:
          - id: M3.3-a1
            met: true
            check: "the darwin-net half is proven by named pure-logic/faked unit tests (no root): TestKubeDNSVIPExemptFromProxy (with WithInfraVIPExemptions the proxy owns the kube-dns VIP for NEITHER 53/TCP nor 53/UDP — no worker, no alias-ensure, no routing entry — while a normal ClusterIP Service IS still claimed, so the exemption is VIP-specific) and TestCoreDNSBoundToDNSVIP (PerNodeDNS renders a Corefile bound to the DNS VIP on :53). The full two-node leg (in-pod resolution of + connection to 10.43.0.1 and 10.43.0.10 from a pod on the NON-control-plane node) is the K3SM_LAB=1 two-Mac gate and needs k3sm:M3.3 (the node-local `kubernetes` endpoint rewrite)."
            method: unit+integration

  - id: M4
    title: NodePort/LB completion + root netd boundary + macOS CI
    status: todo
    depends_on: []
    subphases: []

  - id: M5
    title: vm RuntimeClass networking — NAT (VZNATNetworkDeviceAttachment) guest path + guest-side resolver
    status: in-progress
    depends_on:
      - apis:M5.1
    subphases:
      - id: M5.1
        title: Guest networking for the vm RuntimeClass (Virtualization.framework)
        status: in-progress
        deliverables:
          - id: M5.1-d1
            done: false
            desc: "Guest networking for the `vm` RuntimeClass (Linux micro-VM behind the existing swappable sandbox.Backend seam — runtimed:M5). The lo0-alias + IP_BOUND_IF bind-discipline model is HOST-PROCESS-ONLY: a Virtualization.framework guest has its OWN network stack, so pod connectivity comes from a VZNATNetworkDeviceAttachment (NAT, not bridged — bridged/raw-vmnet needs the Apple-restricted com.apple.vm.networking entitlement, ruled unobtainable; NAT needs only com.apple.security.virtualization), NOT an lo0 alias. LANDED (darwin-net, unit-verifiable): (1) the PATH-SELECTION FORK in pkg/podnet — Network.SetupGuest (BackendVM) allocates the pod IP from the same Allocator but plumbs NO lo0 alias and returns a GuestNetwork (PodIP, NAT gateway/subnet, cluster DNS VIP) for runtimed's VZ backend to apply; Setup (BackendHostProcess) is byte-unchanged; Teardown removes the lo0 alias only for host-process pods. darwin-net provides the config/decision as DATA — the live VZNATNetworkDeviceAttachment wiring is runtimed's (the DAG keeps the VZ backend out of darwin-net). LAB-GATED (scaffold + report, K3SM_LAB=1): the live NAT attach + guest→ClusterIP-VIP reachability (OPEN empirical question: does macOS NAT weak-host-deliver a guest datagram to a host lo0-alias VIP, or only expose the gateway? if not, a host route / a NEW netd route-verb is needed) + cross-node routing. A NAT-private guest IP is NOT yet a cross-node Service backend (same-node scope for M5). Deps apis:M5.1 (the runtime.k3sm.io handler-config mapping runtimeClassName: vm → SANDBOX_BACKEND_VM)."
        acceptance:
          - id: M5.1-a1
            met: false
            check: a pod under runtimeClassName vm is assigned a guest IP via the VZNATNetworkDeviceAttachment and is reachable + can reach a ClusterIP Service and the cluster resolver (lab tier, K3SM_LAB=1)
            method: integration
          - id: M5.1-a2
            met: true
            check: "networking config selects the VM (NAT) path — not the lo0-alias path — when the pod's backend is the VM; the host-process path is unaffected. Proven by the named pure-logic/faked unit test (no root) TestVMPodSelectsVmnetPathNotLo0: a vm pod (SetupGuest) ensures NO lo0 alias and returns a GuestNetwork, while a host-process pod (Setup) ensures exactly one lo0 alias and gets no vmnet config — asserting BOTH the taken and not-taken branch and that teardown removes an alias only for the host-process pod."
            method: unit
      - id: M5.2
        title: Guest-side cluster resolver (the DYLD shim is Darwin-only)
        status: in-progress
        deliverables:
          - id: M5.2-d1
            done: false
            desc: "A guest-side resolver so cluster names (`<svc>.<ns>.svc.cluster.local`, `kubernetes.default.svc`) resolve INSIDE the Linux guest. The Darwin `DYLD_INSERT_LIBRARIES` getaddrinfo shim is meaningless in a Linux guest (no dyld; glibc/musl NSS instead). Point the guest at the cluster resolver via standard Linux mechanisms — render the guest's `/etc/resolv.conf` (nameserver = the kube-dns VIP, search/ndots from the pod DNSConfig). LANDED (darwin-net, unit-verifiable): pkg/dns.GuestResolvConf renders the resolv.conf CONTENT from the M1 netv1.DNSConfig and returns it as DATA for runtimed/k3sm to inject (darwin-net must NOT write the guest rootfs — the DAG forbids it). Two caveats flagged for the injector (not solved here): (a) a Linux guest's DHCP/systemd-resolved will CLOBBER resolv.conf on the NAT interface unless pinned static/immutable; (b) musl (Alpine) largely ignores `options ndots:` where glibc honors it. Reuses the M1 DNSConfig data; replaces only the injection mechanism."
        acceptance:
          - id: M5.2-a1
            met: false
            check: a process inside the vm guest resolves a Service name and kubernetes.default.svc via the cluster resolver using the guest's native resolver (resolv.conf/NSS), with no DYLD shim involved (lab tier, K3SM_LAB=1)
            method: integration

  - id: M7
    title: Public CI workflow + SkipUnless conversions (release-engineering slice — no darwin-net product code)
    status: todo
    depends_on:
      - apis:M7
    subphases:
      - id: M7.1
        title: public CI workflow + SkipUnless conversions
        status: todo
        deliverables:
          - id: M7.1-d1
            done: false
            desc: "`.github/workflows/ci.yml` — the public per-repo CI workflow on a macOS-15 arm64 GitHub Actions runner (the release-engineering slice; NO product-code change). A thin wrapper over the repo's existing commit gates, not a logic duplication (m7-plan M7.2): `gofmt -l .` (must print nothing), `go vet ./...`, `CGO_ENABLED=0 go build ./...`, `CGO_ENABLED=0 go test ./...` and the `-race` pass. darwin-net stays pure Go (`CGO_ENABLED=0`), so the workflow pins that posture explicitly; it mirrors the apis/runtimed/k3sm `ci.yml` shape. The symbol-canary is a k3sm/runtimed concern (darwin-net imports no darwin SPI), so this workflow is the unit + `-race` tier only; the root-gated lo0/pf/utun integration legs remain the nightly sudo-integration workflow's job (m7-plan M7.2), which is out of this repo's slice."
          - id: M7.1-d2
            done: false
            desc: "Convert the repo's raw `t.Skip` integration sites to the apis-hosted `k3smtest.SkipUnless(t, cap)` helper (m7-plan Resolution 4). The affected `//go:build integration` skip sites are the root-gated lo0/pf/utun tests — `TestLo0AliasIdempotentLeakFree`, `TestLo0AliasChurn`, `TestProxyVIPOnRealAlias` (pkg/proxy); `TestPodNetworkSetupTeardownOnRealLo0` (pkg/podnet); `TestMeshDeviceBringUpOnRealUTUN` (pkg/mesh) — each converts from a hand-rolled `t.Skip(\"needs root\")` to `k3smtest.SkipUnless(t, cap)` over the owned capability taxonomy (`root`/`lo0`/`utun`/`pf`). The helper's only DAG-legal home is `k3sm.io/apis` (a leaf copy would drift or force a sideways import — the depends_on edge to apis:M7); the no-raw-`t.Skip`-in-`-tags integration` lint is what keeps the conversion honest, so a self-skip turns red, not silent."
          - id: M7.1-d3
            done: false
            desc: "`README.md` gains the 'part of k3sm' front-door header (the README-refresh-across-all-repos deliverable, m7-plan M7.3): a one-line pitch — pod networking for k3sm (lo0-alias IPAM, userspace Service proxy, wireguard-go mesh, getaddrinfo DNS shim, the PodNetwork seam) — plus the pointer to the umbrella project. No stale-string offenders (e.g. \"Pre-M0 scaffold\") survive the docs stale-string denylist."
        acceptance:
          - id: M7.1-a1
            met: false
            check: "the public CI workflow is green on a PR (gofmt/vet/`CGO_ENABLED=0` build/test + `-race` on a macOS-15 arm64 runner) AND no raw `t.Skip` remains in any `-tags integration` file — every root/lo0/pf/utun skip site routes through the apis-hosted `k3smtest.SkipUnless`, enforced by the no-raw-`t.Skip` lint (a grep-level assert, no root)"
            method: unit

  - id: M8
    title: MLX serving (no darwin-net product work — one S1 exit-criterion verification obligation)
    status: todo
    depends_on:
      - k3sm:M8.0
      - runtimed:M8.2
    subphases:
      - id: M8.1
        title: egress-datapath host-listener address set for the M8.2 golden fixtures (verification obligation)
        status: todo
        deliverables:
          - id: M8.1-d1
            done: false
            desc: "darwin-net has NO product work in M8 (the MLX serving milestone is apis/runtimed/k3sm — machine-checked by the S1 exit criterion). The ONE real obligation this entry carries — so the \"no work\" claim is honest rather than silent — is to provide + pin the production egress datapath's host-listener address set that runtimed's M8.2-d2 golden SBPL fixtures consume. darwin-net owns that datapath (DNS shim → Service-proxy dialer → egress), so it is the authority on which host-listener addresses the path legitimately touches: the DNS/apiserver VIPs, the pod's own lo0 alias, and the mesh-egress /32. runtimed's `allow_internet_egress` branch layers **range-based** host-local denies over the wide IP-scoped allow (m8-plan Resolution 12: deny 127/8, 169.254/16, all of 100.64.0.0/10, the node's RFC1918 subnets, with tier-3 re-allows for the pod's own IP + the cluster VIPs). This enumerated set is what the tier-3 re-allows are pinned against, so those denies do NOT sever the datapath the S1 exit criterion (HF weight download through the production path) must prove. Range-denies keep the set stale-proof against DHCP/mesh address churn. Cross-domain owner: m8-plan Persona Critique → Cross-Domain Conflicts (darwin-systems → pod-networking)."
        acceptance:
          - id: M8.1-a1
            met: false
            check: "the egress-datapath host-listener address set is committed and consumed by the M8.2 golden SBPL fixtures, and the S1 exit-criterion HF-weight download through the production datapath (DNS shim → proxy dialer → egress) succeeds under the FULL d2 egress profile — the range-based host-local denies do not sever it"
            method: integration
---

# darwin-net — Phase roadmap

> Per-repo slice of the k3sm milestones (workspace matrix: `../../ROADMAP.md`; product design:
> `../../k3sm/docs/DESIGN.md` §5b). The YAML frontmatter above is **authoritative**; this prose
> mirrors it. Status: ✅ done · 🟡 in-progress · ⛔ blocked · ⬜ todo.

`darwin-net` is **Wave 2** (with `runtimed`): it imports `apis` and is imported by `k3sm`.

## M0 — (no work) ✅
M0 was a single node advertising the node IP for pods; no Service proxy, IPAM, or mesh. First
`darwin-net` code lands in M1.

## M1 — Services + DNS (single node) 🟡

**Cross-repo deps:** `apis:M1.2` (Service-proxy + DNS-shim shared types); soft-coordinates with
`apis:M1.1` `PodBox` (the pod IP field).

### M1.1 — userspace Service proxy 🟡
**Deliverables**
- ✅ `M1.1-d1` `pkg/proxy`: ClusterIP on an lo0 alias, watch Services/EndpointSlices, L4-LB to local backends; NodePort binds `*:port`. (kube-proxy is never built.) — `RoutingTable` (pure core), `Proxy` (per-VIP serialized workers; ClusterIP binds the specific lo0 alias, NodePort binds `*:port`), `aliasManager` seam (`ifconfig lo0 alias` real impl + rootless fake), `Watcher` (client-go informers). SessionAffinity struck per Wave-0.

**Acceptance (exit gate)**
- ✅ `M1.1-a1` ClusterIP VIP load-balances across endpoints in a faked watch (pure routing table) — *method: unit* → `TestRoutingTableReadyFilter` (unready endpoint NEVER picked), `TestRoutingTablePickDistribution` (round-robin + explicit-index distribution), `TestProxyReconcileLoadBalances` (full reconcile path LBs over ready backends, rootless).
- ✅ `M1.1-a2` lo0 alias create/teardown idempotent + leak-free under churn — *method: integration* → `TestLo0AliasIdempotentLeakFree`, `TestLo0AliasChurn`, `TestProxyVIPOnRealAlias` (build tag `integration`, root-gated `t.Skip`). Logic verified + compiles; the live-root assertion runs under `sudo`/CI (no passwordless sudo in the build session). The rootless tier binds `127.0.0.1` by distinct port — see the macOS note below.

### M1.2 — CoreDNS + getaddrinfo shim 🟡
**Deliverables**
- ✅ `M1.2-d1` `pkg/dns`: CoreDNS on a VIP + the `DYLD_INSERT_LIBRARIES` `getaddrinfo` shim routing pod resolution to CoreDNS. — pure-Go resolver (ndots/search expansion) + CoreDNS `Corefile`/`PodDNSConfig` wiring; the shim is a clang-built C dylib (`shim/getaddrinfo_shim.c`, `hack/build-shim.sh`) keeping Go `CGO_ENABLED=0`.

**Acceptance (exit gate)**
- ✅ `M1.2-a1` a process with the shim resolves a Service via CoreDNS; without it, it does not — *method: integration* → `TestGetaddrinfoShimResolvesViaStub` (build tag `integration`): builds the dylib, `DYLD_INSERT_LIBRARIES`-injects it into a probe, resolves a SHORT name via search through a local stub DNS; the no-shim subtest proves the negative. **Proven in isolation in this repo.** The literal *pod-under-Seatbelt* form is an integration-tier test in the `runtimed` slice (Apple's `sandbox-exec` strips `DYLD_*`; the shim only loads via runtimed's non-platform exec-shim). Resolver/ndots core covered by unit tests (`TestCandidateNamesSearchExpansion`, `TestCandidateNamesShortNameAlwaysSearched`, `TestLookupHostShortNameViaSearch`).

> **macOS rootless-bind note:** unlike Linux's whole `127.0.0.0/8`, only `127.0.0.1` is bindable
> without a root-created `lo0` alias on macOS (verified). So the rootless proxy tests bind `127.0.0.1`
> and distinguish each VIP by port; the faithful per-VIP `127.0.0.x` source-identity rehearsal (a real
> `lo0` alias per VIP) is the root-gated `TestProxyVIPOnRealAlias`.

## M2 — IP-per-pod + bind discipline + in-pod API resolution ✅

**Cross-repo deps:** `apis:M2.1` (the M2 daemon-surface / `PodBox` extension the `PodNetwork` seam
rides). Pairs with `runtimed:M2` (runtimed binds the process; darwin-net provisions the IP).

### M2.1 — IP-per-pod lo0 alias IPAM + the `PodNetwork` seam ✅
**Deliverables**
- ✅ `M2.1-d1` `ifconfig lo0 alias <ip>/32` IPAM from the node's `podCIDR` (per-node /24 out of
  `100.64.0.0/10`); the `PodNetwork` interface `runtimed` calls during pod setup (allocate IP, plumb
  lo0 alias, return the IP to bind). runtimed binds the process to the returned IP via `IP_BOUND_IF`.
  — `pkg/podnet`: `Allocator` (pure-logic IPAM core — `NodeCIDR` per-node /24 carve, unique /32
  allocate/release with leak-tracking, `.0`/`.255` reserved, restart-stable carve), the `aliasManager`
  seam (real `ifconfig lo0 alias` + rootless fake, mirroring `pkg/proxy`), and `Network` implementing
  `PodNetwork` (`Setup`: allocate → ensure alias → return bindable IP, idempotent per pod, rolls back
  the allocation on alias failure; `Teardown`: remove alias → release, leak-free). The returned IP
  flows into the **existing** `runtime/v1` `PodBox.pod_ip` (documented as "the lo0 alias the runtime
  binds the pod's processes to") — **no `apis` change**. The `pf` `k3sm` sub-anchor is deferred to
  **M4** (the root `netd` daemon boundary owns the `pf` sub-anchor).

**Acceptance (exit gate)**
- ✅ `M2.1-a1` IPAM allocate/release is leak-free + idempotent under churn (pure-logic table test);
  the per-node /24 carve is collision-free and stable across restart — *method: unit* →
  `TestNodeCIDRCarveCollisionFree` (disjoint /24s per index; out-of-range fails fast),
  `TestNodeCIDRStableAcrossRestart` (same index ⇒ same /24, no persistence),
  `TestAllocatorUniqueNoDoubleAllocation` (every host once, reserved addrs skipped, exhaustion),
  `TestAllocatorReleaseLeakFree` + `TestAllocatorChurnLeakFree` (release returns to empty; 200-cycle
  churn never leaks), `TestAllocateSpecific`, `TestNewAllocatorRejectsNonSlash24`.
- ✅ `M2.1-a2` `PodNetwork.Setup` plumbs the lo0 alias and returns the bindable IP; teardown removes
  it (root-gated integration on a capable host) — *method: integration* →
  `TestPodNetworkSetupTeardownOnRealLo0`, `TestLo0AliasIdempotentLeakFree`, `TestLo0AliasChurn` (build
  tag `integration`, root-gated `t.Skip`; the live-lo0 assertion runs under `sudo`/CI). The rootless
  unit leg proves the seam with the fake alias manager + a `127/8` bind:
  `TestNetworkSetupAllocatesAndAliases`, `TestNetworkSetupIdempotent`,
  `TestNetworkDistinctPodsDistinctIPs`, `TestNetworkTeardownReleasesAndRemoves`,
  `TestNetworkTeardownIdempotentLeakFree`, `TestNetworkSetupTeardownChurnLeakFree`,
  `TestNetworkSetupRollsBackOnAliasFailure`, `TestNetworkEmptyPodID`.

### M2.2 — in-pod resolution of `kubernetes.default.svc` under the confined runtime ✅
**Reduced to verification + doc** (as the ledger anticipated — no new darwin-net component). The M1
resolver's ndots/search candidate expansion already resolves the in-pod-API name without special-casing:
`kubernetes.default.svc` is just a Service name, so its partial form expands through the search list to
the canonical `kubernetes.default.svc.cluster.local` (the apiserver auto-creates that Service / its
ClusterIP), and a cross-namespace `<svc>.<ns>` form expands to `<svc>.<ns>.svc.cluster.local` — while a
**bare** name stays in the pod's own namespace (the Kubernetes DNS contract). The remaining work was the
**documented constraint**.

**Deliverables**
- ✅ `M2.2-d1` In-pod DNS resolution of `kubernetes.default.svc` (and cluster names generally) under
  Seatbelt confinement. **No new darwin-net code** — proven against the M1 resolver and **documented**
  in `pkg/dns/doc.go` ("In-pod kube-apiserver resolution (M2.2)"). Apple's `sandbox-exec` **strips
  `DYLD_*`** from the child env, so the `DYLD_INSERT_LIBRARIES` getaddrinfo shim only loads under
  runtimed's **non-platform exec-shim** backend; the **decision of record** is to **pin that backend**
  for the in-pod-API resolution path (coordinate with `runtimed:M2`). The **machine-wide DNS-proxy**
  alternative (an mDNSResponder resolver scoped to the cluster domain, injected via `/etc/resolver`) is
  documented as the future option for a platform/confined backend where `DYLD_*` cannot survive.

**Acceptance (exit gate)**
- ✅ `M2.2-a1` a pod resolves `kubernetes.default.svc` via CoreDNS, and the confined-backend limitation
  (`DYLD_*` stripped) is documented with the chosen mitigation (backend pin) — *method: integration* →
  the darwin-net resolution logic is proven by `TestInPodKubernetesAndCrossNamespaceResolution` (the
  partial `kubernetes.default.svc`, its FQDN/trailing-dot forms, and cross-namespace `db.prod` all
  resolve through the candidate-name expansion to the right FQDN; a **bare** `db` does **NOT** cross
  namespaces) and `TestCandidateNamesCrossNamespaceContract` (the same contract at the pure-expansion
  layer). Both are pure-logic table tests, **no root**. Mirroring `M1.2-a1`, the literal
  *pod-under-the-exec-shim-backend* end-to-end leg is a cross-repo integration test in the
  `runtimed`/`k3sm` slice (the backend that keeps `DYLD_*` alive lives there); the darwin-net half — the
  resolver + the documented backend-pin decision — is complete here.

## M3 — wireguard mesh + NodePort + infra-VIP exemption ✅

**Cross-repo deps:** `apis:M3.2` (`MeshPeer` CRD + mesh-enroll payloads — the M3 re-plan split mesh
out of storage `apis:M3.1` into `apis:M3.2`, which darwin-net's mesh depends on). `M3.3` additionally
`depends_on` `k3sm:M3.3` (the node-local `kubernetes` endpoint rewrite). Validated on two real Macs.

### M3.1 — wireguard-go mesh over utun + MeshPeer consumption ✅
**Deliverables**
- ✅ `M3.1-d1` `pkg/mesh` over a root-created `utun` via **wireguard-go** (pinned pseudo-version;
  builds `CGO_ENABLED=0`). Consumes the `net.k3sm.io/v1` `MeshPeer` CRD: `AllowedIPs` per peer = its
  podCIDR, **symmetric**, and the mesh asserts **`AllowedIPs == podnet IPAM CIDR == node.spec.podCIDR`
  (equality, not just symmetry)**. The four load-bearing mechanics from the M3 re-plan — each
  table-tested as **pure logic**, with the privileged ops behind the **`Device` seam** (the netd/root
  boundary):
  - **Per-peer kernel routes** (`route add -net <peer/24> -interface utun`) computed by `RouteSet`
    as a step **distinct** from wg `AllowedIPs` (wireguard-go over a raw utun installs no routes like
    `wg-quick`). `RouteSet` **never** includes this node's own /24 or the `100.64.0.0/10` aggregate.
  - A **reserved mesh-egress /32** (`podnet.MeshEgressIP` = the node /24's `.1`) **excluded from the
    `podnet` allocator** (which used to hand `.1` as the first pod IP — fixed; first pod IP is now
    `.2`) and bound as the Service-proxy backend dialer's `LocalAddr` (`proxy.WithMeshEgressSource`)
    so cross-node return packets land inside peers' `AllowedIPs`.
  - **Watch the `MeshPeer` CRD** (`netv1.AddToScheme` typed informer) and **reconcile** endpoint/key
    changes continuously (not a one-shot read) via a full-resync UAPI.
  - **MTU 1380 + `PersistentKeepalive 25`** (apis constants) and a **minimal `pf scrub max-mss`
    anchor** (pulled forward from M4) clamping `max-mss=1340` **scoped to the utun egress** (never
    lo0). No relay (mutually-routable/same-L2 endpoints). Private keys never leave the node.

**Acceptance (exit gate)**
- ✅ `M3.1-a1` the mesh mechanics are proven by pure-logic named unit tests (no root):
  `TestMeshRoutesPerPeerNotAggregate` (one /24 per peer; own /24 + `/10` aggregate never routed),
  `TestMeshEgressSourceReserved` (mesh `/32` derived from podCIDR **and** excluded from the
  allocator — first pod IP `.2`), `TestMeshAllowedIPsEqualsCIDR` (equality per peer; symmetric-but-
  wrong rejected), `TestMeshReconcileEndpointChange` (an endpoint change reconverges, not ignored).
  The real utun/route/pf bring-up is the wired root-gated `TestMeshDeviceBringUpOnRealUTUN`
  (`//go:build integration`, `t.Skip` without root). Two-real-Macs reachability (`iperf3` both
  directions) + bounce→reconverge is the `K3SM_LAB=1` gate — *method: unit + integration*

### M3.2 — NodePort in the userspace Service proxy (TCP) ✅
**Deliverables**
- ✅ `M3.2-d1` NodePort Services in the userspace Service proxy: a non-zero `ServicePort.NodePort`
  opens a node-wide `*:nodePort` (wildcard) **TCP** listener alongside the ClusterIP listener,
  L4-LB to the **same** ready endpoints (reusing the M1 `RoutingTable`). The listener path existed
  since M1; M3.2 makes it the explicit, documented NodePort path (`proxy.openListener` + `doc.go`
  `# NodePort`). **`externalTrafficPolicy: Cluster` only** — the userspace L4 splice opens a fresh
  backend connection and so does **not** preserve the client source IP, so
  `externalTrafficPolicy: Local` is not honored (documented). **No `apis` change** —
  `ServicePort.NodePort` already exists. **UDP NodePort is DEFERRED** with the UDP datagram relay (a
  UDP port opens no datagram socket on the ClusterIP **or** the NodePort); stockkitty's NodePort
  surface (VSCode SSH `:22`, snapshot gRPC range) is all TCP, so **UDP NodePort is not claimed until
  the relay lands**.

**Acceptance (exit gate)**
- ✅ `M3.2-a1` proven by the named pure-logic/faked unit test (no root) `TestNodePortBindsWildcard`:
  a TCP NodePort Service yields a `*:nodePort` wildcard listener that load-balances across ready
  backends (dialed via loopback), and a UDP NodePort opens **no** listener (relay deferred → not
  claimed); the `externalTrafficPolicy: Cluster` semantics (no client-source-IP preservation through
  the L4 splice) are documented in `pkg/proxy/doc.go` + `openListener`. The live external-client
  reachability on a real `*:nodePort` is the root-gated/lab integration leg — *method: unit +
  integration*

### M3.3 — infra-VIP exemption from podCIDR mesh steering (multi-node correctness) ✅
**Deliverables**
- ✅ `M3.3-d1` Keep the **infra VIPs** — the `kubernetes` ClusterIP (`10.43.0.1`) and the kube-dns
  VIP (`10.43.0.10`) — node-local so they are **never steered over the mesh** (they are **not** in
  any pod's podCIDR, so no peer's symmetric `AllowedIPs` = podCIDR covers them → a mesh-steered infra
  VIP blackholes in-pod kubectl + DNS on multi-node). darwin-net's half: **(1)** per-node CoreDNS
  bound to the DNS VIP — `pkg/dns.PerNodeDNS` renders a Corefile with `bind <DefaultDNSVIP=10.43.0.10>`
  on `:53`, so every node answers cluster DNS over loopback, never the mesh; **(2)** the **kube-dns
  VIP exemption** from proxy ownership for **both `53/TCP` and `53/UDP`** —
  `proxy.WithInfraVIPExemptions` + `Proxy.Reconcile` step aside (no worker, no lo0 alias, no listener,
  no routing entry) so CoreDNS (which binds `10.43.0.10:53` directly) never hits `EADDRINUSE` (the M1
  UDP path only dodged it by accident; TCP had no exemption). **Locality stays a hint** — `classify()`
  is **not** made load-bearing for steering (it mislabels loopback/node-local as remote); infra VIPs
  stay off the utun because the mesh installs kernel routes for peer pod /24s **only** (M3.1
  `RouteSet`), never the `10.43/16` infra range. The `kubernetes` `10.43.0.1` **endpoint rewrite** to
  a node-local apiserver/proxy address is **k3sm-owned** (`k3sm:M3.3`, the `depends_on` edge);
  darwin-net provides the per-node CoreDNS + the exemption seam, and k3sm ensures the `10.43.0.10/32`
  lo0 alias for its per-node CoreDNS (root/netd boundary).

**Acceptance (exit gate)**
- ✅ `M3.3-a1` the darwin-net half is proven by named pure-logic/faked unit tests (no root):
  `TestKubeDNSVIPExemptFromProxy` (with `WithInfraVIPExemptions` the proxy owns the kube-dns VIP for
  **neither** `53/TCP` nor `53/UDP` — no worker, no alias-ensure, no routing entry — while a normal
  ClusterIP Service **is** still claimed, so the exemption is VIP-specific) and
  `TestCoreDNSBoundToDNSVIP` (`PerNodeDNS` renders a Corefile bound to the DNS VIP on `:53`). The full
  two-node leg (in-pod resolution of + connection to `10.43.0.1` and `10.43.0.10` from a pod on the
  **non-control-plane** node) is the `K3SM_LAB=1` two-Mac gate and needs `k3sm:M3.3` (the node-local
  `kubernetes` endpoint rewrite) — *method: unit + integration*

## M4 — Hardening ⬜
Headline: probes/NodePort/LB completion; the root `k3sm-netd` daemon boundary hardened for launchd
(owns lo0 aliases, pf sub-anchor, utun, wireguard — root-only, **no NE entitlement**); macOS-arm64 CI.

## M5 — vm RuntimeClass networking 🟡

**Cross-repo deps:** `apis:M5.1` (the `runtime.k3sm.io` handler-config mapping `runtimeClassName: vm`
→ the existing `SANDBOX_BACKEND_VM`). Pairs with `runtimed:M5` (the Virtualization.framework backend
behind `sandbox.Backend`). The verifiable parts are unit; the live attach + reachability are lab tier
(`K3SM_LAB=1`). **NAT, not bridged**: the guest attaches via `VZNATNetworkDeviceAttachment` (needs only
`com.apple.security.virtualization`); a **bridged/raw-vmnet** attachment needs the Apple-restricted
`com.apple.vm.networking` entitlement, ruled unobtainable — so "bridged" is struck from the deliverable.

### M5.1 — guest networking for the `vm` RuntimeClass 🟡
**Deliverables**
- 🟡 `M5.1-d1` Guest networking for the `vm` RuntimeClass guest (a Linux micro-VM behind the existing
  swappable `sandbox.Backend` seam). The **lo0-alias + `IP_BOUND_IF` bind-discipline model is
  host-process-only**: a Virtualization.framework guest has its **own network stack**, so pod
  connectivity comes from a **`VZNATNetworkDeviceAttachment`** (NAT), **not** an lo0 alias (an lo0
  alias would make the host own the guest's IP and blackhole same-node delivery). **Landed
  (unit-verifiable):** the **path-selection fork** in `pkg/podnet` — `Network.SetupGuest` (`BackendVM`)
  allocates the pod IP from the same `Allocator` but plumbs **no** lo0 alias and returns a
  `GuestNetwork` (PodIP, NAT gateway/subnet, cluster DNS VIP) for runtimed's VZ backend to apply;
  `Setup` (`BackendHostProcess`) is **byte-unchanged**; `Teardown` removes the lo0 alias **only** for
  host-process pods. darwin-net provides the config/**decision as data** — the live
  `VZNATNetworkDeviceAttachment` wiring is runtimed's (the DAG keeps the VZ backend out of darwin-net).
  **Lab-gated remainder (scaffold + report):** the live NAT attach, guest→ClusterIP-VIP reachability
  (**OPEN empirical question** — does macOS NAT weak-host-deliver a guest datagram to a host lo0-alias
  VIP, or only expose the gateway? if not, a host route / a **new `netd` route-verb** is needed), and
  cross-node routing. A NAT-private guest IP is **not yet a cross-node Service backend** (same-node
  scope for M5).

**Acceptance (exit gate)**
- ⬜ `M5.1-a1` a pod under `runtimeClassName: vm` is assigned a guest IP via the
  `VZNATNetworkDeviceAttachment` and is reachable + can reach a ClusterIP Service and the cluster
  resolver — *method: integration* (lab)
- ✅ `M5.1-a2` the networking config selects the VM (NAT) path (**not** the lo0-alias path) when the
  pod's backend is the VM; the host-process path is unaffected — *method: unit* →
  `TestVMPodSelectsVmnetPathNotLo0` (a vm pod via `SetupGuest` ensures **no** lo0 alias and returns a
  `GuestNetwork`; a host-process pod via `Setup` ensures exactly one lo0 alias and gets no vmnet
  config — asserting **both** the taken and not-taken branch, plus that teardown removes an alias only
  for the host-process pod). Also `TestSetupGuestIdempotentAndBackendMismatch`, `TestBackendString`.

### M5.2 — guest-side cluster resolver (the `DYLD` shim is Darwin-only) 🟡
**Deliverables**
- 🟡 `M5.2-d1` A **guest-side resolver** so cluster names (`<svc>.<ns>.svc.cluster.local`,
  `kubernetes.default.svc`) resolve **inside** the Linux guest. The Darwin `DYLD_INSERT_LIBRARIES`
  getaddrinfo shim is **meaningless in a Linux guest** (no dyld; glibc/musl NSS instead). **Landed
  (unit-verifiable):** `pkg/dns.GuestResolvConf` renders the guest's `/etc/resolv.conf` **content**
  (nameserver = the cluster DNS VIP; search/ndots from the pod `DNSConfig`) and returns it as **data**
  for runtimed / the k3sm guest provisioner to inject — darwin-net must **not** write into runtimed's
  guest rootfs (the DAG forbids it). It reuses the M1 `DNSConfig`; only the injection mechanism
  changes. **Two caveats flagged for the injector** (not solved here): (a) a Linux guest's
  DHCP/systemd-resolved will **clobber** resolv.conf on the NAT interface unless pinned
  static/immutable; (b) **musl** (Alpine) largely **ignores `options ndots:`** where glibc honors it.

**Acceptance (exit gate)**
- ⬜ `M5.2-a1` a process inside the `vm` guest resolves a Service name and `kubernetes.default.svc`
  via the cluster resolver using the guest's native resolver (`resolv.conf`/NSS), with **no `DYLD`
  shim** involved — *method: integration* (lab). The darwin-net half — the resolv.conf render — is
  proven by `TestGuestResolvConfRender` (nameserver = the DNS VIP; search/ndots from the `DNSConfig`).

## M7 — public CI workflow + SkipUnless conversions ⬜

**Cross-repo deps:** `apis:M7` (the DAG-legal home for the shared `k3smtest.SkipUnless(t, cap)` helper +
its owned capability taxonomy — m7-plan Resolution 4). The **release-engineering slice** for the public
open-source launch: **no darwin-net product code changes**, just the CI wiring and the test-honesty
conversion (m7-plan M7.2/M7.3).

### M7.1 — public CI workflow + SkipUnless conversions ⬜
**Deliverables**
- ⬜ `M7.1-d1` `.github/workflows/ci.yml` — a thin macOS-15 arm64 workflow over the existing commit
  gates (`gofmt -l`, `go vet`, `CGO_ENABLED=0` build/test, `-race`); darwin-net stays pure Go, so the
  workflow pins `CGO_ENABLED=0`. Mirrors the apis/runtimed/k3sm `ci.yml`; the root-gated lo0/pf/utun
  legs stay in the nightly sudo-integration workflow (out of this repo's slice).
- ⬜ `M7.1-d2` Convert the raw `t.Skip` integration sites (the root-gated lo0/pf/utun tests —
  `TestLo0AliasIdempotentLeakFree`, `TestLo0AliasChurn`, `TestProxyVIPOnRealAlias`,
  `TestPodNetworkSetupTeardownOnRealLo0`, `TestMeshDeviceBringUpOnRealUTUN`) to the **apis-hosted**
  `k3smtest.SkipUnless(t, cap)` helper (m7-plan Resolution 4) over the `root`/`lo0`/`utun`/`pf`
  taxonomy; the no-raw-`t.Skip` lint keeps a self-skip red, not silent.
- ⬜ `M7.1-d3` `README.md` gains the **"part of k3sm"** front-door header (the cross-repo README refresh,
  m7-plan M7.3) — one-line pitch + project pointer, no stale-string offenders.

**Acceptance (exit gate)**
- ⬜ `M7.1-a1` the PR CI workflow is green (gofmt/vet/`CGO_ENABLED=0` build/test + `-race` on macos-15
  arm64) **and** no raw `t.Skip` remains in any `-tags integration` file — every skip site routes
  through `k3smtest.SkipUnless` — *method: unit*

## M8 — MLX serving — (no darwin-net product work) ⬜

**No darwin-net product code lands in M8** — MLX serving is an apis/runtimed/k3sm milestone, and the
"darwin-net has no work" claim is **machine-checked** by the S1 exit criterion (m8-plan). The entry is
kept honest (not silent) by carrying darwin-net's **one** real obligation.

**Cross-repo deps:** `k3sm:M8.0` (the S1 spike) + `runtimed:M8.2` (the `allow_internet_egress` d2
profile whose golden SBPL fixtures consume darwin-net's enumerated set).

### M8.1 — egress-datapath host-listener address set for the M8.2 golden fixtures ⬜
**Deliverables**
- ⬜ `M8.1-d1` Provide + pin the production egress datapath's **host-listener address set** (DNS shim →
  Service-proxy dialer → egress: the DNS/apiserver VIPs, the pod's own lo0 alias, the mesh-egress /32)
  for runtimed's M8.2-d2 golden SBPL fixtures. runtimed's egress branch layers **range-based** host-local
  denies (m8-plan Resolution 12: 127/8, 169.254/16, all of 100.64.0.0/10, node RFC1918 subnets, with
  tier-3 re-allows for the pod IP + cluster VIPs) over the wide IP-scoped allow; darwin-net's enumerated
  set is what the tier-3 re-allows are pinned against, so the denies do **not** sever the datapath S1
  must prove. Range-denies keep it stale-proof. (Cross-domain owner: m8-plan darwin-systems →
  pod-networking conflict resolution.)

**Acceptance (exit gate)**
- ⬜ `M8.1-a1` the address set is committed and consumed by the M8.2 golden SBPL fixtures, and the S1
  HF-weight download through the production datapath succeeds under the **full d2 profile** (the
  range-based host-local denies do not sever it) — *method: integration*

## Next
M1 code is in (`pkg/proxy` + `pkg/dns`, against `apis:M1.2`). To fully close the milestone: run the
root-gated `integration` tests under `sudo` in macOS CI (lo0 alias idempotency + the real-alias VIP),
land the cross-repo pod-under-Seatbelt shim e2e in the `runtimed` slice, and build the UDP datagram
relay + idle-flow GC for `53/UDP` (noted in `pkg/proxy/doc.go`; the routing table is already
protocol-keyed).

**M2** is now decomposed for the `~/stockkitty` readiness work (rationale of record:
`../../docs/stockkitty-readiness.md`): IP-per-pod lo0 IPAM + the `PodNetwork` seam (`M2.1`) plus
in-pod `kubernetes.default.svc` resolution under the confined runtime (`M2.2` — pin the exec-shim
backend or add a DNS proxy, since `sandbox-exec` strips `DYLD_*`). **M3** is code-complete: the
wireguard mesh (`M3.1`), NodePort `*:port` (TCP; UDP relay deferred — `M3.2`), and the **infra-VIP
mesh exemption** (`M3.3` — per-node CoreDNS bound to `10.43.0.10` + the kube-dns VIP exemption from
proxy ownership so the two never fight for `10.43.0.10:53`). The remaining M3 legs are out of
darwin-net's hands: the `K3SM_LAB=1` two-Mac reachability/reconverge gate, the node-local `kubernetes`
endpoint rewrite (`k3sm:M3.3`), and the `53/UDP` datagram relay. **M5** is in progress: the
verifiable parts of the `vm` RuntimeClass guest networking are landed — the **path-selection fork**
(`M5.1`: `podnet.Network.SetupGuest` selects the `VZNATNetworkDeviceAttachment` path with **no** lo0
alias, since the lo0-alias / `IP_BOUND_IF` model is host-process-only) and the **guest resolv.conf
render** (`M5.2`: `dns.GuestResolvConf`, since the `DYLD` getaddrinfo shim is Darwin-only). **NAT, not
bridged** ("bridged" struck — needs the unobtainable `com.apple.vm.networking`). The lab-gated
remainder (`K3SM_LAB=1`) is the live NAT attach, the **guest→ClusterIP-VIP reachability** open
question (and a possible new `netd` route-verb), and cross-node routing — a NAT-private guest IP is
**not yet a cross-node Service backend**. M2 deps `apis:M2.1`; M5 deps `apis:M5.1`.
