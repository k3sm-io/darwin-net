---
repo: darwin-net
schema: phases/v1
current_phase: M5
updated: 2026-08-31
updated_by: orchestrator

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
            desc: "Keep the infra VIPs — the `kubernetes` ClusterIP (10.43.0.1) and the kube-dns VIP (10.43.0.10) — node-local so they are never steered over the wireguard mesh (no peer's symmetric AllowedIPs = podCIDR covers them → a mesh-steered infra VIP blackholes in-pod kubectl + DNS on multi-node). darwin-net's half: (1) a PER-NODE resolver bound to the DNS VIP — the in-process k3sm/pkg/netserve resolver binds `<DefaultDNSVIP=10.43.0.10>` on :53, so every node answers cluster DNS over loopback, never the mesh (renderer deleted 2026-08-29; row reconciled 2026-08-31: darwin-net formerly carried an unconsumed Corefile-rendering exported type for a deferred native-CoreDNS follow-up, deleted 2026-08-29 as unconsumed — see pkg/dns/doc.go); (2) the kube-dns VIP EXEMPTION from proxy ownership for BOTH 53/TCP and 53/UDP — proxy.WithInfraVIPExemptions registers the VIP and Proxy.Reconcile steps aside (no worker, no lo0 alias, no listener, no routing entry) so the per-node resolver (which binds 10.43.0.10:53 directly) never hits EADDRINUSE (the M1 UDP path only dodged the collision by accident; TCP had no exemption). Locality STAYS A HINT: classify() is NOT made load-bearing for steering (it mislabels loopback/node-local as remote) — infra VIPs stay off the utun because the mesh installs kernel routes for peer pod /24s ONLY (M3.1 RouteSet), never the 10.43/16 infra range. The `kubernetes` 10.43.0.1 endpoint rewrite to a node-local apiserver/proxy address is k3sm-owned (k3sm:M3.3, the depends_on edge); darwin-net provides the per-node CoreDNS + the exemption seam, and k3sm ensures the 10.43.0.10/32 lo0 alias for its per-node CoreDNS (root/netd boundary)."
        acceptance:
          - id: M3.3-a1
            met: true
            check: "the darwin-net half is proven by the named pure-logic/faked unit test (no root): TestKubeDNSVIPExemptFromProxy (with WithInfraVIPExemptions the proxy owns the kube-dns VIP for NEITHER 53/TCP nor 53/UDP — no worker, no alias-ensure, no routing entry — while a normal ClusterIP Service IS still claimed, so the exemption is VIP-specific); TestKubeDNSVIPExemptFromProxy is now the surviving proof of the M3.3 darwin-net half (renderer deleted 2026-08-29; row reconciled 2026-08-31 — the retired unit test that proved the now-deleted Corefile-rendering type is removed along with it). The full two-node leg (in-pod resolution of + connection to 10.43.0.1 and 10.43.0.10 from a pod on the NON-control-plane node) is the K3SM_LAB=1 two-Mac gate and needs k3sm:M3.3 (the node-local `kubernetes` endpoint rewrite)."
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
            desc: "`.github/workflows/ci.yml` — the public per-repo CI workflow on a macOS-15 arm64 GitHub Actions runner (the release-engineering slice; NO product-code change). A thin wrapper over the repo's existing commit gates, not a logic duplication: `gofmt -l .` (must print nothing), `go vet ./...`, `CGO_ENABLED=0 go build ./...`, `CGO_ENABLED=0 go test ./...` and the `-race` pass. darwin-net stays pure Go (`CGO_ENABLED=0`), so the workflow pins that posture explicitly; it mirrors the apis/runtimed/k3sm `ci.yml` shape. The symbol-canary is a k3sm/runtimed concern (darwin-net imports no darwin SPI), so this workflow is the unit + `-race` tier only; the root-gated lo0/pf/utun integration legs remain the nightly sudo-integration workflow's job, which is out of this repo's slice."
          - id: M7.1-d2
            done: false
            desc: "Convert the repo's raw `t.Skip` integration sites to the apis-hosted `k3smtest.SkipUnless(t, cap)` helper. The affected `//go:build integration` skip sites are the root-gated lo0/pf/utun tests — `TestLo0AliasIdempotentLeakFree`, `TestLo0AliasChurn`, `TestProxyVIPOnRealAlias` (pkg/proxy); `TestPodNetworkSetupTeardownOnRealLo0` (pkg/podnet); `TestMeshDeviceBringUpOnRealUTUN` (pkg/mesh) — each converts from a hand-rolled `t.Skip(\"needs root\")` to `k3smtest.SkipUnless(t, cap)` over the owned capability taxonomy (`root`/`lo0`/`utun`/`pf`). The helper's only DAG-legal home is `k3sm.io/apis` (a leaf copy would drift or force a sideways import — the depends_on edge to apis:M7); the no-raw-`t.Skip`-in-`-tags integration` lint is what keeps the conversion honest, so a self-skip turns red, not silent."
          - id: M7.1-d3
            done: false
            desc: "`README.md` gains the 'part of k3sm' front-door header (the README-refresh-across-all-repos deliverable): a one-line pitch — pod networking for k3sm (lo0-alias IPAM, userspace Service proxy, wireguard-go mesh, getaddrinfo DNS shim, the PodNetwork seam) — plus the pointer to the umbrella project. No stale-string offenders (e.g. \"Pre-M0 scaffold\") survive the docs stale-string denylist."
        acceptance:
          - id: M7.1-a1
            met: false
            check: "the public CI workflow is green on a PR (gofmt/vet/`CGO_ENABLED=0` build/test + `-race` on a macOS-15 arm64 runner) AND no raw `t.Skip` remains in any `-tags integration` file — every root/lo0/pf/utun skip site routes through the apis-hosted `k3smtest.SkipUnless`, enforced by the no-raw-`t.Skip` lint (a grep-level assert, no root)"
            method: unit

  - id: M8
    title: MLX serving (no darwin-net product work — one S1 exit-criterion verification obligation)
    status: done
    completed: 2026-08-30
    depends_on:
      - k3sm:M8.0
      - runtimed:M8.2
    subphases:
      - id: M8.1
        title: documented egress-datapath address set (input to the FUTURE PF enforcement item) + the S1 exit-criterion verification obligation
        status: done
        completed: 2026-08-30
        deliverables:
          - id: M8.1-d1
            done: true  # 2026-08-30 — the address-set record + the S1 verification, per a1
            desc: "darwin-net still has NO product work in M8. The obligation is re-scoped (2026-08-29, operator-directed per m8-plan R21 — per-IP SBPL scoping does not compile on macOS 26, so no golden fixture consumes an address set): DOCUMENT the production egress datapath's host-listener address set (DNS shim → Service-proxy dialer → egress: the VIPs, the pod's lo0 alias, the mesh-egress /32) as the named input to the FUTURE network-layer (PF) egress enforcement item (backlog B188), in this repo's docs (the datapath authority record). The S1 exit-criterion verification obligation stands: the HF weight download through the production datapath must succeed under the generated egress profile. Cross-domain owner: the darwin-systems → pod-networking datapath boundary."
        acceptance:
          - id: M8.1-a1
            met: true  # 2026-08-30 run5 (rig logs run5-slice-b-egress.log): the probe pod under the generated egress profile fetched the pinned HF file through the production datapath — each link witnessed (cluster DNS via the shim where the host NXDOMAINs; the proxy dialer via the ClusterIP rungs; egress sha-identical to the staged file). The no-annotation counterfactual also succeeded — the documented ceiling, honestly recorded
            check: "the documented address set is committed (datapath-authority record) AND the k3sm:M8.0 S1 findings file records the HF-weight download through the production datapath (DNS shim → proxy dialer → egress) under the generated `allow_internet_egress` profile (rides the S1 evidence)"
            method: integration

  - id: M10
    title: Kubernetes conformance hardening — per-pod-IP DNS record synthesis + L7 Ingress datapath + NetworkPolicy L4 subset
    status: done
    completed: 2026-07-06
    updated_by: orchestrator
    depends_on:
      - runtimed:M10.1
      - k3sm:M10.1
    subphases:
      - id: M10.1
        title: DNS record synthesis (per-pod-A / headless / SRV / PTR) gated on per-pod-/32 wiring
        status: done
        depends_on:
          - runtimed:M10.1
          - k3sm:M10.1
        deliverables:
          - id: M10.1-d1
            done: true
            desc: "Extend the in-process netserve resolver to synthesize per-pod-A / headless (all-backends) / SRV / PTR records from EndpointSlices, gated on the M10.1 per-pod-/32 wiring (runtimed side — depends_on runtimed:M10.1 + k3sm:M10.1, which replaces the `supervisor.NodeNetwork{}` no-op seam with an adapter over `darwin-net/pkg/podnet.Network` so `pod_ip` is a distinct /32, not ≈nodeIP). This is NET-NEW record synthesis, NOT a CoreDNS freebie: the CoreDNS renderer at `pkg/dns/coredns.go` is UNCONSUMED — the live resolver is k3sm's in-process A-record resolver, so headless/SRV/PTR must be built, not enabled. SPLIT THE GATE: (1) SERVER-SIDE record synthesis is CI-provable pure logic over a faked EndpointSlice watch — the unit-testable half, tracked internally, unblocked by hand once M10.1's podnet wiring lands; (2) IN-POD consumption of SRV/PTR needs a getaddrinfo-shim `res_query` extension — a follow-on integration/lab gate, NOT the same slice, because macOS `getaddrinfo` returns only A/AAAA (SRV/PTR ride `res_query`/`res_search`). Reclassifies + CLOSES the register's per-pod-IP / headless / SRV / PTR rows from `honest-limitation (ceiling)` to the correct verdict IN THE SAME CHANGE — per-pod IP is achievable-as-wiring, so leaving `ceiling` ships a known lie."
        acceptance:
          - id: M10.1-a1
            met: true
            check: "server-side record synthesis is proven by pure-logic/faked-watch unit tests (no root, the unit-testable half): `TestHeadlessAndSRVRecordSynthesis` (a headless Service returns the A set of ALL ready backend pod IPs, not a single VIP) plus per-pod-A / SRV / PTR synthesis from a faked EndpointSlice watch — each record type derived from the distinct per-pod /32s the M10.1 podnet wiring now assigns"
            method: unit
          - id: M10.1-a2
            met: false  # LAB-PENDING: code delivered (mesh AllowedIPs already carry pod /24s); the cross-node two-Mac per-pod-IP leg is hack/lab/m10.sh, never auto-greened
            check: "in-pod SRV/PTR consumption is proven by the follow-on integration/lab gate: a pod process resolves an SRV (`_port._proto.<svc>.<ns>.svc.cluster.local`) and a PTR (in-addr.arpa reverse of a pod /32) via the getaddrinfo-shim `res_query` extension — macOS `getaddrinfo` returns only A/AAAA, so this leg exercises the net-new `res_query`/`res_search` path, not the A-record shim"
            method: integration
      - id: M10.3
        title: Ingress L7 datapath — in-process userspace HTTP(S) reverse-proxy in its own package
        status: done
        deliverables:
          - id: M10.3-d1
            done: true
            desc: "An in-process userspace L7 HTTP(S) reverse-proxy in its OWN package (`pkg/ingress` or `pkg/l7`) — NOT accreted onto the L4 `pkg/proxy` (software-architect suggestion; the L4 splice and the L7 router are distinct concerns). Host/path routing, default backend, TLS termination, fronting the ClusterIP VIPs the L4 proxy already owns. Bound to a SPECIFIC node address via the netd `VerbBindPort` fd-passing seam — netd REJECTS a wildcard `*:80`/`*:443` bind (a wildcard L7 listener on the shared node is a cross-tenant footgun). TLS DISCIPLINE: the TLS private key is held IN-PROCESS-MEMORY-ONLY — never written to a pod-reachable path under the shared `_k3sm` uid — and the k3sm IngressClass controller's Secret grant is scoped to the referenced `tls[].secretName`. REJECT a bundled Traefik/nginx binary — it forks the single-binary model. The klipper-lite `status.loadBalancer.ingress = node IP` (closes register B32) is k3sm-owned; darwin-net provides the L7 datapath + the specific-node bind seam."
        acceptance:
          - id: M10.3-a1
            met: true
            check: "host/path routing + default backend + TLS termination fronting a ClusterIP VIP are proven by pure-logic/faked unit tests (no root): a host+path match routes to the right ClusterIP backend, an unmatched request hits the default backend, and the TLS key is verified never to touch a filesystem path (in-memory-only). The specific-node-bind (netd rejects `*:80`) + the real `:80/:443` bring-up via the `VerbBindPort` fd-passing seam is the integration leg; `hack/acceptance/m10-ingress.sh` (host/path route + TLS-from-Secret + `status.loadBalancer`) is the k3sm-owned composite"
            method: unit+integration
      - id: M10.4
        title: NetworkPolicy L4 subset — userspace-proxy dst-VIP allow/deny (policy hint, not isolation)
        status: done
        depends_on:
          - runtimed:M10.1
          - k3sm:M10.1
        deliverables:
          - id: M10.4-d1
            done: true
            desc: "A userspace-proxy dst-VIP allow/deny subset, documented as a POLICY HINT on Service-VIP-mediated ingress ONLY — NOT tenant isolation. THE M10.1→M10.4 CAUSAL LINK (the explicit trade-off): once M10.1 gives each pod its own /32, direct pod-IP→pod-IP traffic over those /32s bypasses the userspace proxy ENTIRELY — M10.1 removes the LAST L4 chokepoint the proxy used to be — so a proxy-mediated NetworkPolicy can only enforce on traffic that still transits a Service VIP. Real tenant isolation (shared lo0 trust domain + a single `_k3sm` uid, so no per-pod uid boundary) is a true platform ceiling: it routes to the `vm` RuntimeClass (M5), NOT to this L4 subset. The register row and `docs/user/limitations.md` carry this as an honest limit (a line-assert), never overstated as isolation. depends_on runtimed:M10.1 + k3sm:M10.1 — the causal link only holds once the per-pod /32s exist."
        acceptance:
          - id: M10.4-a1
            met: true
            check: "the dst-VIP allow/deny subset is proven by the pure-logic unit test `TestNetworkPolicyL4AllowDeny` (a policy allow/deny verdict is applied at the userspace-proxy dst-VIP seam; an allowed VIP is dialed, a denied VIP is refused). The honest limit — that this is a Service-VIP hint and pod-IP→pod-IP over the per-pod /32s bypasses it, so isolation routes to `vm` — is a `docs/user/limitations.md` line-assert, drawing the M10.1→M10.4 causal link"
            method: unit

  - id: M11
    title: Linux containers & multi-arch (darwin-net slice — vm-pod network identity, reachability, policy attribution)
    status: in-progress  # 2026-08-31 — the top-level row lagged its own sub-phases (the ledger-repair defect class)
    depends_on: []
    notes: >-
      First-class design work (upgraded from M5's "same-node open question" prose;
      docs/m11-plan.md §M11.3 is authoritative), driven by spike S5's findings.
      RE-SEQUENCED PRE-LAUNCH (2026-07-11, its R16): ships functional-EXPERIMENTAL at
      v0.1; the network-trust-ceiling text is a LAUNCH-SLICE deliverable (its R22). BINDING
      Phase-B decisions this sub-phase encodes: (a) pod.status.podIP authority for vm
      pods — the guest agent's Health lease is the SINGLE live-address authority (VZ
      exposes no guest-IP API; the "runtimed reconciles from the attachment" comments
      are retired); (b) the Service-backend posture — same-node documented ceiling vs
      the routed-bypass design (vmnet source-NAT is structurally incompatible with the
      mesh's symmetric AllowedIPs, so cross-node NEVER "just works"); (c) the
      probes/port-forward host→guest path; (d) B113 NetworkPolicy source attribution
      (today NAT-rewritten vm-pod traffic hits the proxy's fail-open UNKNOWN-source
      path — the untrusted-tenancy rung must not be the unattributable one). Hard cut:
      a new backend branch in the existing podnet.Backend fork; anything touching
      MeshPeer/AllowedIPs would be a named exception and is explicitly NOT in M11.
    subphases:
      - id: M11.3
        title: guest→VIP reachability + vm-pod identity + source attribution + network-trust ceiling
        status: in-progress  # 2026-08-31 — d1/d3a done, d2/d4 partial (see rows); d3b deferred to v0.1.x (the deferral premise was falsified by the sitting — the operator re-decides the window); the live legs ride the milestone lab gate
        depends_on: [apis:M11.1]
        deliverables:
          - id: M11.3-d1
            done: true  # 2026-08-31 — ANSWERED by the root sitting: delivery works with the guest's bare NAT default route (all four arrangements, TCP+UDP/53), so there is nothing to build — the conditional route-verb item is tombstoned per its own branch clause, the stale OPEN doc comments are retired in this wave, and the live regression leg rides the milestone lab gate
            desc: "guest→VIP reachability: resolve S5(1) — does XNU weak-host-deliver a vmnet-NAT guest packet to a host lo0-alias VIP (every ClusterIP incl. the DNS VIP the guest resolv.conf points at)? If delivery fails, the fix is a NEW netd route verb (root-helper surface — security-critiqued, its own small deliverable) or a host route installed by the unprivileged daemon if sufficient. The M5.1 open question, finally owned."
          - id: M11.3-d2
            done: true  # 2026-09-01 (M11 validation): COMPLETE. The 2026-08-31 note recorded the darwin-net half landed and the TWO-ADDRESS model adopted; the missing consumer half — the published identity actually reaching EndpointSlices — landed in runtimed (createVMPod now stamps the pod's podIP from the GuestNetworker's allocation, distinct from the guest DHCP lease it keeps as the transport address, per the runtime/v1 guest_transport_address MUST-NOT). PROVEN ON HARDWARE: a vm pod reports status.podIP 100.64.0.12, its Service's EndpointSlice carries that /32 with ready=true, a host client reaches the workload through the ClusterIP, and a second vm pod reaches it by Service DNS name. The PodIP-as-guest-eth0-alias branch stays NOT ADOPTED, as recorded — it needs a root-only host route and the shipped model needs no live /32.
            desc: "vm-pod identity: implement the S5(3)-decided podIP model (PodIP-as-guest-eth0-alias + host route, or NAT-address-published) with the consumer matrix reconciled to the ONE authority (EndpointSlices the Service proxy dials, M10 per-pod DNS A/PTR synthesis, downward-API status.podIP in-guest, host-side probe/port-forward dialing); the provider podIP() vm branch retires its nodeIP placeholder. Whichever address is published must be DELIVERABLE — an EndpointSlice/DNS identity nothing can dial is worse than none."
          - id: M11.3-d3a
            done: true  # 2026-08-31 — landed with the wave: the deny is SCOPED by a configured vmnet prefix (a naive deny-all-unknown flip is pinned red by the fail-open-regression and inert-prefix rows, plus the pre-existing L4 table), carries its own machine-distinguishable throttled reason telling the operator this is a known attribution gap and NOT a policy misconfiguration, and the zero/invalid prefix is pinned inert
            desc: "B113a — FAIL-CLOSED unknown vm source (SPLIT 2026-08-30; the in-slice half). This slice CREATES the exposure: today vm pods do not run, so the proxy policy engine's fail-open UNKNOWN-source path is theoretical; making vm pods work turns it into a live NetworkPolicy BYPASS for exactly the pod class NetworkPolicy is most needed for — a regression we introduce, not an inherited ceiling. On a vm-hosting node a source in the vmnet subnet that resolves to no pod is DENIED, but ONLY where a NetworkPolicy actually selects the destination; no-policy destinations stay allowed (upstream semantics), so the m11-core legs are unaffected. Mechanical, unit-testable on the existing table, no hardware. Converts a fail-open into a fail-closed."
          - id: M11.3-d3b
            done: false
            desc: "B113b — real source ATTRIBUTION (SPLIT 2026-08-30; DEFERRED to v0.1.x). B113 NetworkPolicy source attribution: register the guest address→pod mapping with the Service-proxy policy engine on agent-Health lease report WITH a lease-change liveness contract (DHCP addresses move across guest restarts; the deterministic MAC makes leases semi-stable — S5(5) verifies), or flip unknown-source to deny on vm-hosting nodes. Closes the fail-open UNKNOWN path (proxy policy.go ALLOW+Warn) for the one pod class NetworkPolicy most needs to constrain. Depends on S5(5) lease stability and S5(6) source-address observation; if S5(6) records that vmnet rewrites the source to the gateway address, per-pod attribution is IMPOSSIBLE as specified and d3a's fail-closed becomes the permanent answer."
          - id: M11.3-d4
            done: true  # 2026-09-01 (M11 validation): COMPLETE. The user-facing half the 2026-08-31 note deferred to the milestone docs deliverable has landed in docs/user/limitations.md, and it is a MEASUREMENT rather than the hedged wording: with two vm pods live on the rig, guest->guest is BLOCKED (TCP refused, ICMP 100% loss) and guest->host-LAN is BLOCKED, while guest->ClusterIP/DNS-VIP and guest->internet are reachable. That is NARROWER than this deliverable's desc assumed (it assumed guest<->guest at NAT addresses bypasses Services/policy) — so the ceiling is recorded as stronger isolation, and explicitly as an observed platform property of the NAT rather than something k3sm enforces, so no reader mistakes it for a policy guarantee. No pf rules were added.
            desc: "Network-trust ceiling recorded: the S5(4) guest↔guest + guest→LAN reachability matrix is a SECURITY fact — guests share one vmnet NAT segment (guest↔guest at NAT addresses bypasses Services/policy; unfiltered L3 to the gateway/LAN). Lands in docs/user/limitations.md + the register wording, or a pf-filter-on-the-vmnet-member follow-up is scoped as its own forward-marker. Guest link MTU ≤1380 in the DHCP/init plan if cross-node is ever claimed (the mesh mss-clamp is utun-scoped and does not cover non-TCP guest traffic)."
        acceptance:
          - id: M11.3-a1
            met: false
            check: "the identity/attribution logic is unit-proven at the seams (B113a's fail-closed table incl. the fail-open-regression negative and the no-policy-destination-still-allowed row — the IN-SLICE half of the 2026-08-30 d3a/d3b split; B113b's TestVMPodSourceAttribution stale-lease table rides d3b at v0.1.x; the podIP-authority consumer matrix as pure translation tables, encoding the TWO-ADDRESS model: the podCIDR /32 is the PUBLISHED identity (box.PodIp, downward-API status.podIP, EndpointSlice, DNS) and the agent-Health vmnet lease is the LIVE TRANSPORT address (host->guest dial, attribution), never published — R2 and R3 cannot both govern one address, since the lease exists only after boot and the env is baked before it); the LIVE legs — guest→VIP delivery, host→guest dial, guest DNS resolution, the Service-consumed leg — ride hack/lab/m11.sh (K3SM_LAB=1, human-run), never auto-greened"
            method: unit

  - id: M14
    title: Destination-scoped mesh-egress source binding (the server-mesh enabler)
    status: todo
    strategy: hard cut
    depends_on: []
    note: "darwin-net's single slice of the workspace M14 program (authoritative input: docs/m14-plan.md, sub-phase M14.2-d1; the rest of M14 is k3sm-side and lab work). It exists because k3sm CANNOT bring the server onto the mesh until this lands: the server's proxy would otherwise source-bind EVERY backend dial to a mesh-egress address, which is the documented 'breaks ALL backend dials' hazard and the reason k3sm leaves netserve.Config.MeshEgressIP deliberately empty today. Scoping the bind at the DIALER is what keeps the whole program hard cut — it is a unilateral per-node decision no peer observes, so no MeshPeer/AllowedIPs protocol change (and no named exception) is triggered."
    subphases:
      - id: M14.0
        title: bind the mesh-egress source only for foreign pod-CIDR destinations
        status: todo
        strategy: hard cut
        depends_on: []
        deliverables:
          - id: M14.0-d1
            done: false
            desc: "Select the dial source PER CONNECTION from the already-precomputed backend.Locality(): bind the mesh-egress source only when the destination is inside podnet.ClusterPodCIDR AND outside this node's own /24. Every other destination — loopback, a ClusterIP VIP splicing to a local backend, a node LAN address, upstream — keeps kernel default source selection. LocalityUnknown NEVER binds (the zero/invalid-podCIDR state that classify() fails open for in the ROUTING decision must fail to the kernel default here, not to a bind; the two decisions have opposite safe directions). IMPLEMENTATION IS CONSTRAINED, not free: use two IMMUTABLE dialers chosen per dial, or a connection-local dialer value — NEVER mutate the shared p.dialer.LocalAddr, which is a data race across the per-connection handle() goroutines and would reintroduce the wrong-source blackhole non-deterministically instead of uniformly. The UDP relay already does this correctly with a per-flow local; mirror that shape."
          - id: M14.0-d2
            done: false
            desc: "BOTH protocols get identical scoping. The TCP dial path and the UDP relay's per-flow source must apply the same predicate — the UDP half is exactly the half a TCP-only functional test cannot see, so an asymmetry here ships as UDP Services silently failing against hostNetwork/LAN backends."
          - id: M14.0-d3
            done: false
            desc: "This also closes a LATENT WORKER-SIDE defect, not just the server enabler: today's unconditional bind blackholes any dial whose destination is a node LAN address (a hostprocess pod reports podIP == nodeIP), because the reply routes back over the peer's utun and wireguard drops it as outside the sender's AllowedIPs. Rejected alternative, recorded: widening AllowedIPs to include node LAN /32s would break the AllowedIPs == podCIDR equality invariant pkg/mesh/doc.go asserts AND trip the phased MeshPeer-protocol named exception."
          - id: M14.0-d4
            done: false
            desc: "Retire or rewrite pkg/proxy/meshegress_test.go's TestWithMeshEgressSourceBindsDialer, which asserts the construction-time 'bind once, unconditionally' contract this deliberately replaces. Left in place it either goes red for the right reason or — worse — stays green while asserting nothing about production behaviour, because WithMeshEgressSource would keep setting a field the new dial path no longer reads."
        acceptance:
          - id: M14.0-a1
            met: false
            check: "unit tables over the scoping decision for BOTH TCP and UDP (foreign /24 => bound; own /24, loopback, node LAN, ClusterIP VIP, and LocalityUnknown => unbound), run under -race with concurrent local- and remote-destination dials so the per-connection shared-state property is actually exercised rather than assumed; the construction-time bind test is rewritten. The cross-node datapath proof rides the k3sm two-Mac lab (hack/lab/m3.sh, K3SM_LAB=1), never auto-greened here"
            method: unit
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
  VIP blackholes in-pod kubectl + DNS on multi-node). darwin-net's half: **(1)** a per-node resolver
  bound to the DNS VIP — the in-process `k3sm/pkg/netserve` resolver binds `<DefaultDNSVIP=10.43.0.10>`
  on `:53`, so every node answers cluster DNS over loopback, never the mesh (renderer deleted
  2026-08-29; row reconciled 2026-08-31: darwin-net formerly carried an unconsumed
  Corefile-rendering exported type for a deferred native-CoreDNS follow-up, deleted 2026-08-29 as
  unconsumed — see `pkg/dns/doc.go`); **(2)** the **kube-dns
  VIP exemption** from proxy ownership for **both `53/TCP` and `53/UDP`** —
  `proxy.WithInfraVIPExemptions` + `Proxy.Reconcile` step aside (no worker, no lo0 alias, no listener,
  no routing entry) so the per-node resolver (which binds `10.43.0.10:53` directly) never hits `EADDRINUSE` (the M1
  UDP path only dodged it by accident; TCP had no exemption). **Locality stays a hint** — `classify()`
  is **not** made load-bearing for steering (it mislabels loopback/node-local as remote); infra VIPs
  stay off the utun because the mesh installs kernel routes for peer pod /24s **only** (M3.1
  `RouteSet`), never the `10.43/16` infra range. The `kubernetes` `10.43.0.1` **endpoint rewrite** to
  a node-local apiserver/proxy address is **k3sm-owned** (`k3sm:M3.3`, the `depends_on` edge);
  darwin-net provides the per-node resolver + the exemption seam, and k3sm ensures the `10.43.0.10/32`
  lo0 alias for its per-node resolver (root/netd boundary).

**Acceptance (exit gate)**
- ✅ `M3.3-a1` the darwin-net half is proven by the named pure-logic/faked unit test (no root):
  `TestKubeDNSVIPExemptFromProxy` (with `WithInfraVIPExemptions` the proxy owns the kube-dns VIP for
  **neither** `53/TCP` nor `53/UDP` — no worker, no alias-ensure, no routing entry — while a normal
  ClusterIP Service **is** still claimed, so the exemption is VIP-specific); `TestKubeDNSVIPExemptFromProxy`
  is now the surviving proof of the M3.3 darwin-net half (renderer deleted 2026-08-29; row reconciled
  2026-08-31 — the retired unit test that proved the now-deleted Corefile-rendering type is removed
  along with it). The full
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
its owned capability taxonomy). The **release-engineering slice** for the public
open-source launch: **no darwin-net product code changes**, just the CI wiring and the test-honesty
conversion.

### M7.1 — public CI workflow + SkipUnless conversions ⬜
**Deliverables**
- ⬜ `M7.1-d1` `.github/workflows/ci.yml` — a thin macOS-15 arm64 workflow over the existing commit
  gates (`gofmt -l`, `go vet`, `CGO_ENABLED=0` build/test, `-race`); darwin-net stays pure Go, so the
  workflow pins `CGO_ENABLED=0`. Mirrors the apis/runtimed/k3sm `ci.yml`; the root-gated lo0/pf/utun
  legs stay in the nightly sudo-integration workflow (out of this repo's slice).
- ⬜ `M7.1-d2` Convert the raw `t.Skip` integration sites (the root-gated lo0/pf/utun tests —
  `TestLo0AliasIdempotentLeakFree`, `TestLo0AliasChurn`, `TestProxyVIPOnRealAlias`,
  `TestPodNetworkSetupTeardownOnRealLo0`, `TestMeshDeviceBringUpOnRealUTUN`) to the **apis-hosted**
  `k3smtest.SkipUnless(t, cap)` helper over the `root`/`lo0`/`utun`/`pf`
  taxonomy; the no-raw-`t.Skip` lint keeps a self-skip red, not silent.
- ⬜ `M7.1-d3` `README.md` gains the **"part of k3sm"** front-door header (the cross-repo README
  refresh) — one-line pitch + project pointer, no stale-string offenders.

**Acceptance (exit gate)**
- ⬜ `M7.1-a1` the PR CI workflow is green (gofmt/vet/`CGO_ENABLED=0` build/test + `-race` on macos-15
  arm64) **and** no raw `t.Skip` remains in any `-tags integration` file — every skip site routes
  through `k3smtest.SkipUnless` — *method: unit*

## M8 — MLX serving — (no darwin-net product work) ⬜

**No darwin-net product code lands in M8** — MLX serving is an apis/runtimed/k3sm milestone, and the
"darwin-net has no work" claim is **machine-checked** by the S1 exit criterion. The entry is
kept honest (not silent) by carrying darwin-net's **one** real obligation.

**Cross-repo deps:** `k3sm:M8.0` (the S1 spike, whose findings file carries this entry's evidence) +
`runtimed:M8.2` (the `allow_internet_egress` d2 profile the S1 download runs under). *Re-scoped
2026-08-29, operator-directed per m8-plan R21 — no golden fixture consumes an address set.*

### M8.1 — documented egress-datapath address set (PF-future input) + the S1 verification obligation ⬜
**Deliverables**
- ⬜ `M8.1-d1` darwin-net still has **no product work** in M8. The obligation is re-scoped
  (2026-08-29, operator-directed per **m8-plan R21** — per-IP SBPL scoping does not compile on macOS 26,
  so no golden fixture consumes an address set): **DOCUMENT** the production egress datapath's
  **host-listener address set** (DNS shim → Service-proxy dialer → egress: the VIPs, the pod's lo0 alias,
  the mesh-egress /32) as the named input to the **FUTURE network-layer (PF) egress enforcement item**
  (backlog B188), in this repo's docs (the datapath authority record). The S1 exit-criterion
  verification obligation stands: the HF weight download through the production datapath must succeed
  under the generated egress profile. (Cross-domain owner: the darwin-systems → pod-networking
  datapath boundary.)

**Acceptance (exit gate)**
- ✅ `M8.1-a1` record committed 2026-08-31 (`docs/EGRESS-DATAPATH.md`); the S1-findings half rides
  the k3sm findings file as recorded. The documented address set is committed (datapath-authority
  record) **and** the
  `k3sm:M8.0` S1 findings file records the HF-weight download through the production datapath
  (DNS shim → proxy dialer → egress) under the generated `allow_internet_egress` profile
  (rides the S1 evidence) — *method: integration*

## M10 — Kubernetes conformance hardening ⬜

**Cross-repo deps:** `runtimed:M10.1` + `k3sm:M10.1` (the per-pod-IP wiring — replacing the
`supervisor.NodeNetwork{}` no-op seam with an adapter over `pkg/podnet.Network` so `pod_ip` is a
distinct `/32`, not ≈nodeIP). **Scope: conformance hardening, not a certification** —
k3sm cannot pass Sonobuoy `[Conformance]`; M10 raises honest fidelity where the Darwin substrate
allows. darwin-net's slices are M10.1 (DNS record synthesis), M10.3 (Ingress L7 datapath), and M10.4
(NetworkPolicy L4 subset); M10.0 (apiserver config) and M10.2 (workload-execution fidelity) carry no
darwin-net product code.

### M10.1 — DNS record synthesis (per-pod-A / headless / SRV / PTR) ⬜
**Deliverables**
- ⬜ `M10.1-d1` Extend the in-process netserve resolver to synthesize **per-pod-A / headless
  (all-backends) / SRV / PTR** records from EndpointSlices, gated on the M10.1 per-pod-`/32` wiring
  (runtimed side). **Net-new record synthesis, NOT a CoreDNS freebie** — the CoreDNS renderer at
  `pkg/dns/coredns.go` is **unconsumed**; the live resolver is k3sm's in-process A-record resolver, so
  headless/SRV/PTR must be **built**, not enabled. **Split the gate:** the **server-side** synthesis is
  CI-provable pure logic (the unit-testable half, tracked internally as B81 — `status: done` since the
  `podnet` wiring landed; this read `blocked` until 2026-07-31); **in-pod** SRV/PTR consumption needs a **getaddrinfo-shim `res_query`
  extension** — a follow-on integration/lab gate, since macOS `getaddrinfo` returns only A/AAAA
  (SRV/PTR ride `res_query`). Reclassifies + **closes the register's per-pod-IP rows** from
  `honest-limitation (ceiling)` to the correct verdict in the same change.

**Acceptance (exit gate)**
- ⬜ `M10.1-a1` server-side synthesis proven by pure-logic/faked-watch unit tests —
  `TestHeadlessAndSRVRecordSynthesis` (all ready backend pod IPs, not one VIP) + per-pod-A/SRV/PTR
  from a faked EndpointSlice watch — *method: unit* (the unit-testable half)
- ⬜ `M10.1-a2` in-pod SRV/PTR resolution via the getaddrinfo-shim `res_query` extension (an SRV +
  a PTR reverse of a pod `/32`) — *method: integration* (lab; the follow-on gate)

### M10.3 — Ingress L7 datapath ⬜
**Deliverables**
- ⬜ `M10.3-d1` An in-process userspace **L7 HTTP(S) reverse-proxy in its OWN package** (`pkg/ingress`
  or `pkg/l7`) — **not** accreted onto the L4 `pkg/proxy`. Host/path routing, default backend, **TLS
  termination**, fronting the ClusterIP VIPs. Bound to a **specific node address** via the netd
  `VerbBindPort` fd-passing seam (**netd rejects `*:80`**). The **TLS private key stays
  in-process-memory-only** — never a pod-reachable path under the shared `_k3sm` uid — and the
  IngressClass controller's Secret grant is scoped to the referenced `tls[].secretName`.
  **Reject a bundled Traefik binary** (it forks the single-binary model). The klipper-lite
  `status.loadBalancer` is k3sm-owned.

**Acceptance (exit gate)**
- ⬜ `M10.3-a1` host/path route + default backend + TLS termination proven by faked/pure-logic unit
  tests (the TLS key never touches a filesystem path); the specific-node bind + real `:80/:443` via
  `VerbBindPort` is the integration leg; `hack/acceptance/m10-ingress.sh` is the k3sm composite —
  *method: unit + integration*

### M10.4 — NetworkPolicy L4 subset ⬜
**Deliverables**
- ⬜ `M10.4-d1` A userspace-proxy dst-VIP **allow/deny subset**, documented as a **policy hint on
  Service-VIP-mediated ingress ONLY — NOT tenant isolation**. **The M10.1→M10.4 causal link**:
  once M10.1 gives each pod its own `/32`, direct pod-IP→pod-IP traffic **bypasses the proxy entirely**
  — M10.1 removes the **last L4 chokepoint** — so the policy can only enforce on Service-VIP transit.
  Real isolation (shared lo0 + single `_k3sm` uid) routes to the **`vm`** RuntimeClass (M5), not this
  L4 subset. Depends on `runtimed:M10.1` + `k3sm:M10.1` — the causal link only holds once the per-pod
  `/32`s exist.

**Acceptance (exit gate)**
- ⬜ `M10.4-a1` `TestNetworkPolicyL4AllowDeny` (an allow/deny verdict at the userspace-proxy dst-VIP
  seam — allowed VIP dialed, denied VIP refused); the honest limit (pod-IP→pod-IP bypasses; isolation
  routes to `vm`) is a `docs/user/limitations.md` line-assert — *method: unit*

## Next
M1 code is in (`pkg/proxy` + `pkg/dns`, against `apis:M1.2`). To fully close the milestone: run the
root-gated `integration` tests under `sudo` in macOS CI (lo0 alias idempotency + the real-alias VIP),
land the cross-repo pod-under-Seatbelt shim e2e in the `runtimed` slice, and build the UDP datagram
relay + idle-flow GC for `53/UDP` (noted in `pkg/proxy/doc.go`; the routing table is already
protocol-keyed).

**M2** is now decomposed for the reference-workload readiness work: IP-per-pod lo0 IPAM + the
`PodNetwork` seam (`M2.1`) plus
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

## M11 — Linux containers & multi-arch (darwin-net slice) ⬜
First-class design work, upgraded from M5's "same-node open question" prose (`docs/m11-plan.md`
§M11.3 authoritative; spike **S5** supplies the empirical inputs). **Hard cut** — a new backend
branch in the existing `podnet.Backend` fork; nothing touches MeshPeer/AllowedIPs (that would be a
named exception, explicitly out of M11).

### M11.3 — vm-pod identity, reachability, attribution, trust ceiling ⬜
**Cross-repo dep:** `apis:M11.1` (the Health lease report). **BINDING decisions encoded here**
(fed by S5): the agent-Health lease is the **single live-address authority** for a vm pod; the
Service-backend posture (same-node documented ceiling vs a routed bypass of vmnet's source-NAT —
which breaks symmetric AllowedIPs, so cross-node never "just works"); the probes/port-forward
host→guest path; B113 source attribution (closing the proxy's fail-open UNKNOWN path for
NAT-rewritten guest traffic).
**Deliverables** — frontmatter `M11.3-d1…d4`: d1 guest→VIP delivery (possible new `netd` route
verb — root-helper surface, security-critiqued); d2 the podIP model + consumer matrix
(EndpointSlices, per-pod DNS A/PTR, downward-API, probe dialing) reconciled to the one authority;
d3 B113 attribution with a lease-change liveness contract; d4 the network-trust ceiling recorded
(guest↔guest / guest→LAN segment facts → limitations.md/register, or a pf-filter forward-marker).
**Acceptance** — frontmatter `M11.3-a1`: seams unit-proven; every live leg rides
`hack/lab/m11.sh` (`K3SM_LAB=1`), never auto-greened.
