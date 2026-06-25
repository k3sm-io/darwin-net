---
repo: darwin-net
schema: phases/v1
current_phase: M1
updated: 2026-06-24
updated_by: orchestrate/M1

phases:
  - id: M0
    title: Walking skeleton (no darwin-net work — single node, node IP only)
    status: done
    completed: 2026-06-24
    depends_on: []
    subphases: []

  - id: M1
    title: Services + DNS (single node) — userspace Service proxy + CoreDNS + getaddrinfo shim
    status: in-progress
    depends_on:
      - apis:M1.2
    subphases:
      - id: M1.1
        title: Userspace Service proxy (ClusterIP)
        status: in-progress
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
        status: in-progress
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
    title: IP-per-pod (lo0 alias IPAM + bind discipline) + PodNetwork seam
    status: todo
    depends_on: []
    subphases: []

  - id: M3
    title: wireguard-go mesh over utun + MeshPeer consumption
    status: todo
    depends_on:
      - apis:M3.1
    subphases: []

  - id: M4
    title: NodePort/LB completion + root netd boundary + macOS CI
    status: todo
    depends_on: []
    subphases: []
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

## M2 — IP-per-pod + bind discipline ⬜
Decomposed when M1 closes. Headline: `ifconfig lo0 alias <ip>/32` IPAM from the node's `podCIDR`
(per-node /24 out of `100.64.0.0/10`); the `PodNetwork` interface `runtimed` calls during pod setup
(allocate IP, plumb lo0 alias, return the IP to bind); a `pf` `k3sm` sub-anchor. Pairs with
`runtimed:M2` (runtimed binds the process; darwin-net provisions the IP).

## M3 — wireguard mesh ⬜
Headline (deps `apis:M3.1` `MeshPeer`): `pkg/mesh` over a root-created `utun`; `AllowedIPs` per peer =
its podCIDR; unique per-node /24 ⇒ routed not NAT'd; MTU 1380 + `pf scrub max-mss`;
`PersistentKeepalive 25`; consume peer keys/endpoints from the `MeshPeer` CRD (private keys never
leave the node). Validated on two real Macs (`iperf3` both directions; bounce a node → reconverge).

## M4 — Hardening ⬜
Headline: probes/NodePort/LB completion; the root `k3sm-netd` daemon boundary hardened for launchd
(owns lo0 aliases, pf sub-anchor, utun, wireguard — root-only, **no NE entitlement**); macOS-arm64 CI.

## Next
M1 code is in (`pkg/proxy` + `pkg/dns`, against `apis:M1.2`). To fully close the milestone: run the
root-gated `integration` tests under `sudo` in macOS CI (lo0 alias idempotency + the real-alias VIP),
land the cross-repo pod-under-Seatbelt shim e2e in the `runtimed` slice, and build the UDP datagram
relay + idle-flow GC for `53/UDP` (noted in `pkg/proxy/doc.go`; the routing table is already
protocol-keyed). Then decompose M2 (IP-per-pod + `PodNetwork` seam).
