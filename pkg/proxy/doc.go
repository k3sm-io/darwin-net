/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package proxy is k3sm's userspace Service proxy: the macOS-native analog of
// kube-proxy (which is Linux-only and never built here). It owns one listening
// socket per ClusterIP:port — bound on a dedicated lo0 alias so loopback stamps
// the VIP as the source identity — plus a node-wide *:NodePort socket when a
// port declares one, and L4-load-balances accepted connections to the Ready
// backends watched from the Services/EndpointSlices APIs.
//
// # Layers
//
//   - RoutingTable (routing.go) is the pure-logic core: ClusterIP:port → ordered
//     Ready backends, with a deterministic round-robin picker (Pick), an
//     explicit-index picker (PickAt) for table-assertable distribution, and a
//     ClientIP-session-affinity picker (PickSticky, affinity.go) layered over the
//     same activePool policy. Only Ready endpoints are ever admitted (SetEndpoints
//     filters at the single admission point), so an unready endpoint can never be
//     selected. It carries no sockets and no client-go types, so its behavior is
//     fully unit-tested.
//   - aliasManager (alias.go) abstracts lo0 alias create/teardown. The production
//     lo0AliasManager shells out to `ifconfig lo0 alias <ip>/32`; it is root-gated,
//     so in deployment the proxy plumbs VIP aliases through the root netd daemon
//     (WithNetdHelper) or runs the manager directly as root. Unit tests use the
//     rootless noopAliasManager; the root-gated integration test creates real lo0
//     aliases for 127.0.0.x VIPs (on Darwin only 127.0.0.1 is bindable without an
//     alias) for a faithful per-VIP source-identity rehearsal.
//   - Proxy (proxy.go) owns the sockets and enforces per-VIP serialization: each
//     ClusterIP:port is reconciled by exactly one worker goroutine fed by a
//     per-key channel, so a Service event and an EndpointSlice event for the same
//     port can never race two owners onto one socket or close a live listener.
//   - serviceToVIP / endpointsForPort (translate.go) are pure translators from
//     corev1.Service / discoveryv1.EndpointSlice to the netv1 contract types, so
//     the watch→proxy mapping (including the Ready-condition handling) is
//     table-testable without an apiserver.
//   - Watcher (watch.go) is the production seam: client-go shared informers feed
//     Service/EndpointSlice events into Proxy.Reconcile.
//
// # NodePort (M3.2)
//
// A Service port with a non-zero NodePort additionally opens a node-wide
// *:NodePort TCP listener (bound to the wildcard so every node interface answers)
// that L4-load-balances to ALL Ready backends. The NodePort listener is bound
// IN-PROCESS (a plain net.Listen on the wildcard); it never goes through the root
// netd helper, which binds only specific-address ports and rejects the wildcard — a
// >=1024 wildcard needs no privilege, so there is no helper NodePort path.
//
// The NodePort path is externalTrafficPolicy: Cluster and is a DISTINCT selector from
// the ClusterIP path: it calls RoutingTable.PickCluster (the external scope of the
// shared activePool), which routes to every Ready backend and IGNORES
// internalTrafficPolicy: Local. internalTrafficPolicy governs the ClusterIP
// (east-west) path ONLY, externalTrafficPolicy governs NodePort (KEP-2086), so an
// iTP:Local Service still serves its NodePort to all backends rather than dropping
// when the node has no local endpoint — the *:NodePort listener no longer shares the
// ClusterIP's iTP:Local filter (a plain external listener would otherwise inherit the
// key's iTP and blackhole NodePort traffic on a node with only remote backends). Two
// deliberate divergences follow:
//
//   - externalTrafficPolicy: Local is NOT honored — the userspace splice opens a
//     fresh backend connection and so does not preserve the external client's source
//     IP (the precondition Local relies on), so an eTP:Local Service gets Cluster
//     behavior on its NodePort.
//   - ClientIP session affinity is NOT applied on the NodePort path. A direct external
//     client's real source IP IS visible (so affinity COULD apply), but threading it
//     now collides with the in-flight affinity work; it is an explicit, documented
//     deferral to a follow-up. NodePort connections round-robin the Cluster pool.
//
// SECURITY CAVEAT: internalTrafficPolicy:Local is NOT a mesh-containment boundary for a
// Service that ALSO exposes a NodePort. The *:NodePort listener binds the wildcard
// (reachable over the wireguard mesh and lo0), and PickCluster routes to remote backends,
// so any pod that can dial nodeIP:NodePort reaches remote backends the iTP:Local ClusterIP
// path would drop. iTP:Local bounds only the ClusterIP (east-west) selector, never the
// NodePort surface — treat it as a routing policy, not an isolation control.
//
// A note on the iTP:Local fail-open (ClusterIP path): the degrade-to-Cluster fires on
// !podCIDR.IsValid() ONLY (an unset/malformed podCIDR) — a VALID but wrong prefix
// still DROPS, because podCIDR drives lo0 alias allocation, so a valid prefix that
// misclassifies every backend as remote is precluded by construction.
//
// NodePort is TCP only: the ClusterIP UDP datagram relay (below) is built, but the
// UDP NodePort is deferred, because a wildcard *:NodePort UDP reply re-selects its
// source by route lookup on a multi-homed node (the client would see the wrong
// source IP and drop it). stockkitty's NodePort surface (VSCode SSH :22, the
// snapshot gRPC range) is all TCP, so UDP NodePort is not claimed.
//
// # Locality (load-bearing only for internalTrafficPolicy: Local)
//
// Backend locality (local lo0 pod IP vs remote pod over the wireguard mesh) is
// computed proxy-side from the node podCIDR with a cheap netip.Prefix.Contains —
// no getifaddrs scan per connection. For cluster-default Services it is a
// hint/metric only: cross-node steering is done by the per-peer kernel routes the
// mesh installs on the utun (pkg/mesh, M3.1), not by this classifier, and Pick
// round-robins over every Ready backend regardless of locality. classify mislabels
// any address outside the node podCIDR — including loopback and node-local infra
// VIPs — as remote, so cluster-default routing never gates on it; infra VIPs stay
// node-local for free because the mesh routes only peer pod /24s to the utun, so
// 10.43.0.10 / 10.43.0.1 are never steered over it.
//
// Locality becomes load-bearing for exactly ONE decision: internalTrafficPolicy:
// Local backend selection under a VALID node podCIDR (routing.go Pick). There the
// table filters to the LocalityLocal subset, dropping (ErrNoLocalBackends → the
// listener closes the accepted conn) when no backend is node-local — the faithful
// upstream no-fallback. Under a zero/invalid podCIDR (locality is unknowable) Pick
// fails open to all backends with a loud Warn rather than blackhole the Service.
// Two divergences from upstream kube-proxy are deliberate and documented:
//
//   - k3sm derives locality from podCIDR.Contains(endpointIP), NOT upstream's
//     endpoint.nodeName == thisNode. This is faithful for k3sm's pod-backed
//     Services — every pod is an lo0 alias IP inside the node podCIDR by
//     construction, so "IP in podCIDR" is equivalent to "on this node" — but it
//     would misclassify a host-network or otherwise non-pod endpoint, which the
//     Darwin-process pod path never produces. If such endpoints are ever modeled,
//     locality must move to a nodeName-equivalent signal.
//   - On a no-local-backend drop the userspace listener has already accepted the
//     TCP connection, so the client sees connect-then-RST rather than upstream's
//     iptables SYN-drop. This is immaterial to conformance: reachability fails
//     either way, only the L4 shape of the failure differs.
//
// internalTrafficPolicy: Local is routing/affinity, NOT a tenancy boundary: a
// same-node pod can still reach any backend by dialing the pod IP or a NodePort
// directly. It steers Service-VIP traffic; it does not isolate.
//
// # Infra-VIP exemption (per-node resolver) — M3.3
//
// k3sm runs a per-node resolver (the in-process k3sm/pkg/netserve resolver; the
// pkg/dns.PerNodeDNS Corefile is the unconsumed native-CoreDNS export) on every
// node bound directly to the kube-dns VIP (10.43.0.10) for 53/TCP and 53/UDP, so
// cluster DNS is always answered node-locally over loopback and never crosses the
// mesh. WithInfraVIPExemptions registers that VIP so the proxy yields ownership of
// it entirely — no lo0 alias, no socket, no routing entry — which is what keeps
// the proxy from colliding with the resolver on 10.43.0.10:53 (EADDRINUSE). The exemption is keyed on the VIP
// address, so it covers both 53/TCP and 53/UDP; a normal ClusterIP Service is
// unaffected. The node-local kubernetes (10.43.0.1) endpoint uses the same
// step-aside mechanism, but its endpoint rewrite is k3sm-owned (k3sm:M3.3) —
// darwin-net supplies the per-node DNS Corefile render (pkg/dns.PerNodeDNS) and
// this exemption seam.
//
// # UDP datagram relay (ClusterIP) + idle-flow GC — B23
//
// A ClusterIP UDP Service is served by a connectionless datagram relay
// (udprelay.go); there is no Accept/CloseWrite. One dispatcher goroutine reads
// datagrams on the VIP PacketConn (bound on the specific lo0 alias, mirroring the
// TCP specific-bind) and, per client 5-tuple: (a) selects a backend ONCE via the
// routing table (Pick — the relay never re-picks per datagram), (b) opens a
// connected per-flow upstream UDP socket, (c) forwards the datagram, and (d) spawns
// a reader that writes each backend response back to the client with the VIP as the
// source. A sweeper goroutine expires a flow after udpFlowIdleTimeout of two-way
// silence (Linux conntrack-UDP / kube-proxy's userspace udpIdleTimeout) so cached
// sockets and the backend selection do not pin to a dead client. The flow table is
// bounded (maxUDPFlows): same-node pods share one trust domain with no per-pod
// isolation, so ephemeral-source-port churn from one pod must not exhaust fds and
// goroutines for every Service the proxy owns — on saturation a new flow is dropped
// (a throttled Warn), never a live one evicted.
//
// # UDP fair-share + fd budget — B48
//
// Two further admission gates harden the relay against one same-node pod
// monopolizing a VIP or exhausting the co-resident control plane's fds. A per-source
// sub-cap (maxUDPFlowsPerSource = maxUDPFlows/4) bounds any single source IP's
// concurrent flows PER VIP, so a pod cycling ephemeral source ports cannot fill a
// VIP's whole table and starve every other pod's access to that Service. A
// relay-GLOBAL fd budget (an atomic udpBudget shared by every per-VIP relay via New)
// bounds concurrent upstream sockets across ALL relays, so the datagram relays cannot
// jointly exhaust the process fd table. Both counters are an EXACT function of flows
// membership — incremented only at the authoritative second-lock insert, decremented
// only at a flow delete (idle sweep or Close) — so an admission that drops a flow
// never mis-accounts and the caps can never silently stop firing; a doomed dial is
// still rejected with the socket closed so no fd leaks on rejection.
//
// The budget is an OPEN-LOOP static reservation of the relay's fd slice, NOT a live
// whole-daemon governor: TCP proxy handles and the kine/apiserver clients spend from
// the same process fd table UNCOUNTED. Its default is half the enforced soft
// RLIMIT_NOFILE, floored at maxUDPFlows so a low launchd soft limit never regresses a
// single VIP below its B23 per-VIP capacity; the k3sm assembler — which alone sees
// the whole process fd table — sizes it deliberately via WithUDPFlowBudget, because a
// leaf subsystem must not unilaterally partition a process-global resource.
// Fair-share is PER VIP: a pod fanning flows across N distinct VIPs can still reach
// the global budget; a per-source-GLOBAL sub-cap is a follow-up.
//
// Like the TCP splice the relay RE-ORIGINATES traffic (Cluster policy): it does NOT
// preserve the client pod source IP. On a multi-node mesh each upstream socket is
// source-bound to the node's mesh-egress /32 (WithMeshEgressSource) — the UDP path
// cannot reuse p.dialer because a *net.TCPAddr LocalAddr fails to dial "udp", so it
// builds a *net.UDPAddr — or wireguard would drop the cross-node return datagram.
// B23 has no conntrack-style flush, so a flow stays pinned to its picked backend
// until idle GC reaps it, even if that endpoint is removed mid-flow.
//
// DEFERRED in B23: UDP NodePort (a wildcard *:NodePort UDP reply re-selects its
// source by route lookup on a multi-homed node → wrong source IP → the client drops
// it; honoring it needs IP_RECVDSTADDR/IP_SENDSRCADDR) and privileged (<1024) UDP
// via the netd helper (the binder seam returns net.Listener/FileListener — stream
// only — and cannot adopt a datagram fd, so a <1024 UDP ClusterIP without root
// surfaces an honest net.ListenPacket EACCES rather than a helper-bound socket).
// The cluster-DNS VIP (10.43.0.10:53) never reaches the relay: the address-keyed
// infra-VIP exemption (WithInfraVIPExemptions) steps the proxy aside before any
// worker is created, so a legitimate USER UDP Service on a non-exempt VIP is relayed
// while kube-dns stays node-local on its own resolver.
//
// # ClientIP session affinity (TCP) — B22
//
// A Service with sessionAffinity: ClientIP pins every connection from one client IP
// to the same backend. The Watcher reads svc.Spec.SessionAffinity (+
// SessionAffinityConfig.ClientIP.TimeoutSeconds, nil-safely defaulted to 3h — never
// infinite) in serviceToVIP and threads it, like internalTrafficPolicy, to the
// routing table; netv1 carries no SessionAffinity field (only the proxy consumes it).
// The TCP accept path calls RoutingTable.PickSticky (proxy.handle) instead of Pick.
//
// PickSticky is a cache OVER Pick, not a replacement for its policy: it shares the
// same activePool (the Ready + internalTrafficPolicy:Local-filtered pool with the B21
// fail-open/ErrNoLocalBackends semantics), so a sticky pick and a round-robin pick can
// never disagree on which backends are eligible. A binding is reused only when the
// bound backend is STILL in the live active pool (re-validated in O(1) against a
// precomputed membership set) AND within the idle TTL; a backend that went unready or
// (under iTP:Local) left the node-local subset is re-picked, never reused, so affinity
// never dials a dead backend nor spills node-local traffic across the mesh, and a
// port with no node-local backend left DROPS (ErrNoLocalBackends). The binding map is
// TABLE-level (guarded by the routing lock, folded in so there is no second lock to
// order), so it SURVIVES endpoint churn — SetEndpointsPolicy replaces the portState on
// every reconcile, which would wipe a per-portState map. Bindings are idle-swept by a
// single Proxy-owned ticker (SweepExpired is a pure, clock-injected table method — the
// table stays goroutine-free) and bounded per port, and are purged when affinity is
// toggled off or the port is deleted so a re-enable never resurrects stale stickiness.
//
// Two limitations are deliberate and documented:
//
//   - Cross-node fidelity: affinity keys on the source IP THIS proxy sees. Same-node
//     ClusterIP traffic arrives on loopback carrying the real pod lo0 IP (faithful),
//     but cross-node and NodePort traffic is re-originated from the peer node's
//     mesh-egress /32 (the userspace splice does not preserve the client src IP —
//     DESIGN §5b), so all cross-node clients behind one peer collapse to a SINGLE
//     affinity binding. This is a userspace-L4 limitation, not a bug.
//   - UDP affinity is DEFERRED (TCP-only). The ClusterIP UDP relay (B23) reuses a
//     backend per client 5-tuple for the life of a flow, but that is flow-affinity,
//     NOT per-client-IP sessionAffinity: it keys on the full 5-tuple (not the IP
//     alone) and does not span reconnects. udprelay.go still calls Pick, unchanged.
package proxy
