---
repo: darwin-net
schema: phases/v1
current_phase: M1
updated: 2026-06-24
updated_by: human

phases:
  - id: M0
    title: Walking skeleton (no darwin-net work — single node, node IP only)
    status: done
    completed: 2026-06-24
    depends_on: []
    subphases: []

  - id: M1
    title: Services + DNS (single node) — userspace Service proxy + CoreDNS + getaddrinfo shim
    status: todo
    depends_on:
      - apis:M1.2
    subphases:
      - id: M1.1
        title: Userspace Service proxy (ClusterIP)
        status: todo
        deliverables:
          - id: M1.1-d1
            done: false
            desc: pkg/proxy — userspace Service proxy owning each ClusterIP:port on an lo0 alias, watching Services/EndpointSlices, L4 load-balancing to local backends (NodePort binds *:port)
        acceptance:
          - id: M1.1-a1
            met: false
            check: a ClusterIP VIP load-balances across backend endpoints in a faked watch; the routing table is pure-logic table-tested
            method: unit
          - id: M1.1-a2
            met: false
            check: lo0 alias create/teardown is idempotent and leak-free under churn (root-gated integration; rootless path binds 127/8)
            method: integration
      - id: M1.2
        title: CoreDNS wiring + getaddrinfo shim
        status: todo
        deliverables:
          - id: M1.2-d1
            done: false
            desc: pkg/dns — wire CoreDNS as the cluster resolver on a VIP plus a DYLD_INSERT_LIBRARIES getaddrinfo/res_* shim routing pod name resolution to CoreDNS (not resolv.conf — macOS uses mDNSResponder)
        acceptance:
          - id: M1.2-a1
            met: false
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

## M1 — Services + DNS (single node) ⬜

**Cross-repo deps:** `apis:M1.2` (Service-proxy + DNS-shim shared types); soft-coordinates with
`apis:M1.1` `PodBox` (the pod IP field).

### M1.1 — userspace Service proxy ⬜
**Deliverables**
- ⬜ `M1.1-d1` `pkg/proxy`: ClusterIP on an lo0 alias, watch Services/EndpointSlices, L4-LB to local backends; NodePort binds `*:port`. (kube-proxy is never built.)

**Acceptance (exit gate)**
- ⬜ `M1.1-a1` ClusterIP VIP load-balances across endpoints in a faked watch (pure routing table) — *method: unit*
- ⬜ `M1.1-a2` lo0 alias create/teardown idempotent + leak-free under churn — *method: integration*

### M1.2 — CoreDNS + getaddrinfo shim ⬜
**Deliverables**
- ⬜ `M1.2-d1` `pkg/dns`: CoreDNS on a VIP + the `DYLD_INSERT_LIBRARIES` `getaddrinfo`/`res_*` shim routing pod resolution to CoreDNS.

**Acceptance (exit gate)**
- ⬜ `M1.2-a1` a pod with the shim resolves a Service via CoreDNS; without it, it does not — *method: integration*

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
M1.1 — `pkg/proxy` routing table (pure unit-tested) then the lo0-alias integration path, against the
`apis:M1.2` Service types.
