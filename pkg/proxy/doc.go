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
//     same activePool policy. Only Ready endpoints are admitted (SetEndpoints
//     filters at the single admission point). It carries no sockets and no
//     client-go types, so its behavior is fully unit-tested.
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
//     Service/EndpointSlice events into Proxy.Reconcile. The per-VIP worker above
//     serializes delivery, not the recompute that produces what is delivered — the
//     Watcher's own per-Service stripe lock keeps a stale snapshot from landing on
//     top of a fresh one.
//
// # NodePort
//
// A Service port with a non-zero NodePort additionally opens a node-wide
// *:NodePort TCP listener (bound to the wildcard so every node interface answers)
// that L4-load-balances to all Ready backends. The NodePort listener is bound
// in-process (a plain net.Listen on the wildcard); it never goes through the root
// netd helper, which binds only specific-address ports and rejects the wildcard — a
// >=1024 wildcard needs no privilege, so there is no helper NodePort path.
//
// The NodePort path is externalTrafficPolicy: Cluster and is a distinct selector from
// the ClusterIP path: it calls RoutingTable.PickStickyCluster (the external scope of
// the shared activePool), which routes to every Ready backend and ignores
// internalTrafficPolicy: Local. internalTrafficPolicy governs the ClusterIP
// (east-west) path only, externalTrafficPolicy governs NodePort (KEP-2086), so an
// iTP:Local Service still serves its NodePort to all backends rather than dropping
// when the node has no local endpoint — the *:NodePort listener no longer shares the
// ClusterIP's iTP:Local filter.
//
// ClientIP session affinity is applied on the NodePort path too, over the
// Cluster pool: PickStickyCluster is PickSticky's external-scope sibling (both are
// thin wrappers over pickStickyScoped), so a sessionAffinity: ClientIP Service pins
// each client IP to a backend from the full Ready set — the iTP:Local subset never
// applies to NodePort. The bindings share the port's table-level sub-map with the
// ClusterIP path (same PortKey; see pickStickyScoped). One divergence remains:
//
//   - externalTrafficPolicy: Local is not honored — the userspace splice opens a
//     fresh backend connection and so does not preserve the external client's source
//     IP (the precondition Local relies on), so an eTP:Local Service gets Cluster
//     behavior on its NodePort. The Watcher surfaces this at the datapath: onService
//     reads eTP only to emit a once-per-episode throttled Warn when a Service
//     requests eTP:Local on a served NodePort — it never changes routing. That
//     datapath Warn complements k3sm's admission-side VAP
//     pkg/policy.EnsureExternalTrafficPolicyLocalWarn, giving node-local
//     observability at the exact point traffic diverges as defense-in-depth for this
//     independent module.
//
// Security caveat: internalTrafficPolicy:Local is not a mesh-containment boundary for
// a Service that also exposes a NodePort. The *:NodePort listener binds the wildcard
// (reachable over the wireguard mesh and lo0), and PickStickyCluster routes to remote
// backends, so any pod that can dial nodeIP:NodePort reaches remote backends the
// iTP:Local ClusterIP path would drop. iTP:Local bounds only the ClusterIP (east-west)
// selector, never the NodePort surface — treat it as a routing policy, not an isolation
// control.
//
// A note on the iTP:Local fail-open (ClusterIP path): the degrade-to-Cluster fires
// only on !podCIDR.IsValid() (an unset/malformed podCIDR) — a valid but wrong prefix
// still drops, because podCIDR drives lo0 alias allocation, so a valid prefix that
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
// mesh installs on the utun (pkg/mesh), not by this classifier, and Pick
// round-robins over every Ready backend regardless of locality. classify mislabels
// any address outside the node podCIDR — including loopback and node-local infra
// VIPs — as remote, so cluster-default routing never gates on it; infra VIPs stay
// node-local for free because the mesh routes only peer pod /24s to the utun, so
// 10.43.0.10 / 10.43.0.1 are never steered over it.
//
// Locality is load-bearing for exactly one decision: internalTrafficPolicy:
// Local backend selection under a valid node podCIDR (routing.go Pick). There the
// table filters to the LocalityLocal subset, dropping (ErrNoLocalBackends → the
// listener closes the accepted conn) when no backend is node-local — the faithful
// upstream no-fallback. Under a zero/invalid podCIDR (locality is unknowable) Pick
// fails open to all backends with a loud Warn rather than blackhole the Service.
// Two divergences from upstream kube-proxy are documented:
//
//   - k3sm derives locality from podCIDR.Contains(endpointIP), not upstream's
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
// # Infra-VIP exemption (per-node resolver)
//
// k3sm runs a per-node resolver (the in-process k3sm/pkg/netserve resolver) on
// every node bound directly to the kube-dns VIP (10.43.0.10) for 53/TCP and
// 53/UDP, so cluster DNS is always answered node-locally over loopback and never
// crosses the mesh. WithInfraVIPExemptions registers that VIP so the proxy yields
// ownership of it entirely — no lo0 alias, no socket, no routing entry — which is
// what keeps the proxy from colliding with the resolver on 10.43.0.10:53
// (EADDRINUSE). The exemption is keyed on the VIP address, so it covers both
// 53/TCP and 53/UDP; a normal ClusterIP Service is unaffected. The node-local
// kubernetes (10.43.0.1) endpoint uses the same step-aside mechanism, but its
// endpoint rewrite is k3sm-owned — darwin-net supplies the DNS-VIP
// default (pkg/dns.DefaultDNSVIP) and this exemption seam.
//
// # UDP datagram relay (ClusterIP) + idle-flow GC
//
// A ClusterIP UDP Service is served by a connectionless datagram relay
// (udprelay.go); there is no Accept/CloseWrite. One dispatcher goroutine reads
// datagrams on the VIP PacketConn (bound on the specific lo0 alias, mirroring the
// TCP specific-bind) and, per client 5-tuple: (a) selects a backend once via the
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
// # UDP fair-share + fd budget
//
// Further admission gates harden the relay against one same-node pod monopolizing a
// VIP or exhausting the co-resident control plane's fds. A per-source sub-cap
// (maxUDPFlowsPerSource = maxUDPFlows/4) bounds any single source IP's concurrent
// flows per VIP, so a pod cycling ephemeral source ports cannot fill a VIP's whole
// table and starve every other pod's access to that Service. A relay-global budget (a
// mutex-guarded udpBudget shared by every per-VIP relay via New) then enforces two
// more caps under one lock: it bounds concurrent upstream sockets across all relays
// (so the datagram relays cannot jointly exhaust the process fd table) and bounds any
// one source IP's flows across all VIPs (maxPerSource = maxTotal/4, the
// per-source-global fair share), so a pod fanning flows across N distinct VIPs cannot
// consume the whole global budget and starve every other pod on every VIP. Every
// counter is incremented only at the authoritative second-lock insert and decremented
// only at a flow delete (idle sweep or Close), so an admission that drops a flow never
// mis-accounts and a doomed dial is still rejected with the socket closed (no fd leak
// on rejection). reserve is all-or-nothing (it moves the global-total and per-source
// counts together, never split), because a partial reserve with a rollback would be
// the counter-leak shape that permanently locks a source out on every VIP.
//
// The budget is a static reservation of the relay's fd slice, not a live whole-daemon
// governor: TCP proxy handles and the kine/apiserver clients spend from the same
// process fd table, uncounted here. Its default is half the enforced soft
// RLIMIT_NOFILE, floored at maxUDPFlows so a low launchd soft limit never regresses a
// single VIP below its per-VIP capacity; the k3sm assembler — which alone sees
// the whole process fd table — sizes it via WithUDPFlowBudget, because a leaf
// subsystem must not unilaterally partition a process-global resource. The
// per-source caps are DoS-resistance / fairness within the same-node shared trust
// domain, not tenant isolation: same-node pods share one trust domain (no per-pod
// uid) and a source-spoofing pod evades the per-source bucket — untrusted workloads
// belong in a vm RuntimeClass.
//
// Like the TCP splice the relay re-originates traffic (Cluster policy): it does not
// preserve the client pod source IP. On a multi-node mesh an upstream socket is
// source-bound to the node's mesh-egress /32 (WithMeshEgressSource) — or wireguard
// would drop the cross-node return datagram — but only for a cross-node pod
// destination: the bind is destination-scoped and both protocols share one
// predicate (egressScope.sourceFor), so a same-node, node-LAN, loopback or
// unclassifiable destination keeps kernel default source selection on the datagram
// path exactly as it does on the stream path. The UDP path cannot reuse the mesh
// *net.Dialer because a *net.TCPAddr LocalAddr fails to dial "udp", so it builds a
// *net.UDPAddr from that same verdict. The relay has no conntrack-style flush, so a flow
// stays pinned to its picked backend until idle GC reaps it, even if that endpoint
// is removed mid-flow.
//
// Deferred: UDP NodePort (a wildcard *:NodePort UDP reply re-selects its
// source by route lookup on a multi-homed node → wrong source IP → the client drops
// it; honoring it needs IP_RECVDSTADDR/IP_SENDSRCADDR) and privileged (<1024) UDP
// via the netd helper (the binder seam returns net.Listener/FileListener — stream
// only — and cannot adopt a datagram fd, so a <1024 UDP ClusterIP without root
// surfaces an honest net.ListenPacket EACCES rather than a helper-bound socket).
// The cluster-DNS VIP (10.43.0.10:53) never reaches the relay: the address-keyed
// infra-VIP exemption (WithInfraVIPExemptions) steps the proxy aside before any
// worker is created, so a legitimate user UDP Service on a non-exempt VIP is relayed
// while kube-dns stays node-local on its own resolver.
//
// # ClientIP session affinity (TCP)
//
// A Service with sessionAffinity: ClientIP pins every connection from one client IP
// to the same backend. The Watcher reads svc.Spec.SessionAffinity (+
// SessionAffinityConfig.ClientIP.TimeoutSeconds, nil-safely defaulted to 3h — never
// infinite) in serviceToVIP and threads it, like internalTrafficPolicy, to the
// routing table; netv1 carries no SessionAffinity field (only the proxy consumes it).
// The TCP accept path calls RoutingTable.PickSticky (proxy.handle) instead of Pick.
//
// PickSticky is a cache over Pick, not a replacement for its policy: it shares the
// same activePool (the Ready + internalTrafficPolicy:Local-filtered pool with the
// fail-open/ErrNoLocalBackends semantics), so a sticky pick and a round-robin pick can
// never disagree on which backends are eligible. A binding is reused only when the
// bound backend is still in the live active pool (re-validated in O(1) against a
// precomputed membership set) and within the idle TTL; a backend that went unready or
// (under iTP:Local) left the node-local subset is re-picked, never reused, so affinity
// never dials a dead backend nor spills node-local traffic across the mesh, and a
// port with no node-local backend left drops (ErrNoLocalBackends). The binding map is
// table-level (guarded by the routing lock, folded in so there is no second lock to
// order), so it survives endpoint churn — SetEndpointsPolicy replaces the portState on
// every reconcile, which would wipe a per-portState map. Bindings are idle-swept by a
// single Proxy-owned ticker (SweepExpired is a pure, clock-injected table method — the
// table stays goroutine-free) and bounded per port, and are purged when affinity is
// toggled off or the port is deleted so a re-enable never resurrects stale stickiness.
//
// Two limitations are documented:
//
//   - Cross-node fidelity: affinity keys on the source IP this proxy sees. Same-node
//     ClusterIP traffic arrives on loopback carrying the real pod lo0 IP (faithful),
//     and the NodePort path applies the same ClientIP affinity over the Cluster pool.
//     But cross-node mesh-forwarded traffic is re-originated from the peer
//     node's mesh-egress /32 (the userspace splice does not preserve the client src IP
//     — DESIGN §5b), so all cross-node clients behind one peer collapse to a single,
//     coarse affinity binding (still re-validated to a Ready backend on every hit,
//     never a wrong route). This is a userspace-L4 limitation, not a bug.
//   - UDP affinity is deferred (TCP-only). The ClusterIP UDP relay reuses a
//     backend per client 5-tuple for the life of a flow, but that is flow-affinity,
//     not per-client-IP sessionAffinity: it keys on the full 5-tuple (not the IP
//     alone) and does not span reconnects. udprelay.go still calls Pick, unchanged.
//
// # Published identity vs live transport — the vm-pod two-address seam
//
// A backend's address in the routing table is its published identity: what the
// EndpointSlice carries, what cluster DNS answers, what status.podIP reports, and
// what a NetworkPolicy names. For a host-process pod that address is also where the
// bytes go — it is a /32 alias the host owns on lo0. For a vm-RuntimeClass pod it is
// not: the guest owns its address inside its own netstack behind a NAT attachment,
// the host never aliases the pod /32, and the address that actually carries bytes is
// the guest's macOS-assigned vmnet DHCP lease, which is never published.
//
// RoutingTable.SetTransportOverrides is the one seam where those two meet — a
// published-to-live address map, replaced wholesale, consulted only at the dial
// sites (proxy.handle for TCP, udpRelay.upstreamFor for UDP; both protocols, so a vm
// backend cannot be reachable over one and blackholed over the other). Pick, the
// NetworkPolicy verdict, the deny log and the ClientIP affinity binding all keep
// using the published address, because that is the stable identity a lease change
// must not disturb. A backend with no override is dialed exactly as before, which is
// what leaves every host-process pod untouched; for a vm pod an absent override
// means undialable, and the dial fails as any unreachable backend's does — the table
// never substitutes an address to paper over a missing lease. The feeder is the k3sm
// assembler (from the guest agent's Health lease report) and it does not exist yet,
// so no override is installed today.
//
// # NetworkPolicy L4 subset — VIP-mediated ingress hint, NOT isolation
//
// PolicyTable (policy.go) + PolicyWatcher (policywatch.go) add an
// upstream-faithful restriction of NetworkPolicy ingress enforcement at the
// userspace proxy's accept paths. The verdict is per (source addr, picked backend
// pod IP, backend port), evaluated after the routing table picks the backend —
// TCP in handle post-Pick, UDP at relay flow admission (the once-per-flow pick in
// upstreamFor; a denied flow is never created) — never per VIP/Service, because
// one Service can front policy-heterogeneous pods. Semantics: a backend no policy
// selects is allowed (default-allow-unless-selected); a selected backend admits a
// source iff any policy's resolved ingress rule matches source and port (union of
// allows); otherwise deny. The PolicyWatcher resolves selectors (NetworkPolicy +
// Pod + Namespace informers — namespaceSelector matches namespace labels) into
// concrete /32 source sets and port sets via a debounced full recompute
// (policyRecomputeDebounce; O(policies × pods) is microseconds at k3sm scale and
// wholesale replacement keeps the table trivially consistent), installed
// atomically via PolicyTable.Update. Convergence after an API change is bounded
// by informer latency plus the debounce window; the table is empty (allow
// everything) until WaitForCacheSync — fail-open, never a partial-cache deny.
//
// The honest ceiling (the per-pod-/32 causal link): once each pod has its own
// /32, direct pod-IP→pod-IP traffic bypasses the userspace proxy entirely — the
// proxy is no longer an L4 chokepoint — so this subset enforces only on traffic
// that transits a Service VIP. All headless/StatefulSet traffic (which resolves
// to pod IPs, never a VIP) bypasses it, as does any direct pod-IP dial. The
// PolicyWatcher Warns once per policy about exactly this. Policies aimed at infra
// VIPs the proxy yields via WithInfraVIPExemptions (the kube-dns VIP, the
// rewritten kubernetes endpoint) are likewise unenforceable — exempt VIPs never
// transit the hooked accept paths. Real tenant isolation (shared lo0 trust
// domain, single _k3sm uid) routes to the vm RuntimeClass, never to this
// hint.
//
// Widen-only discipline: an inexpressible clause may only widen allows, never
// manufacture a deny upstream would not have. Deferred (widened or ignored
// accordingly): ipBlock peers (widen the rule to any-source), all egress rules
// (policyTypes: Egress is ignored entirely; an egress-only policy selects nothing
// for ingress), named ports / endPort ranges / protocol-only port entries (widen
// the rule to any-port), and the rule's protocol field (ignored — a TCP-only
// allow also admits UDP on that port).
//
// Availability guardrails (fail-open by design): loopback sources and the
// constructor-seeded always-allow /32s (node InternalIP, this node's and every
// peer's mesh-egress /32) always pass, so node-origin dialers — the in-process
// Ingress datapath, apiserver webhooks, hostNetwork clients — and re-originated
// cross-node mesh traffic are never locked out by a pod policy (cross-node
// sources collapse to the peer's mesh-egress /32, the same L4 fidelity limit
// session affinity documents, so per-pod cross-node attribution is impossible
// here). An unknown source (not a resolved pod IP, not always-allowed) is allowed
// with a throttled Warn naming it; a deny is a throttled Info. A nil PolicyTable
// (the default — the k3sm assembler opts in via WithPolicyTable) allows
// everything: the feature is strictly additive.
//
// One scoped exception to that fail-open: on a node built with
// NewPolicyTableVMNet, an unknown source inside the configured vmnet segment whose
// destination a policy selects is denied, with its own throttled Warn. That source
// class is the vm pods this node hosts, whose live vmnet lease nothing maps back to
// a pod yet — under the fail-open they would walk past a policy that selects the
// destination, a bypass for exactly the pod class the vm RuntimeClass exists to
// contain. The scoping keeps it a vm-only decision: every other unknown source, and
// every node with no vmnet prefix, keeps the fail-open verbatim. Until the
// lease-to-pod registry lands, a policy `from` rule naming a vm pod's published /32
// cannot admit that pod's live traffic — this deny is what that gap looks like.
package proxy
