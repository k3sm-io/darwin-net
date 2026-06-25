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
//     Ready backends, with a deterministic round-robin picker (Pick) and an
//     explicit-index picker (PickAt) for table-assertable distribution. Only
//     Ready endpoints are ever admitted (SetEndpoints filters at the single
//     admission point), so an unready endpoint can never be selected. It carries
//     no sockets and no client-go types, so its behavior is fully unit-tested.
//     SessionAffinity is intentionally out of scope for M1: this is round-robin
//     only.
//   - aliasManager (alias.go) abstracts lo0 alias create/teardown. The production
//     lo0AliasManager shells out to `ifconfig lo0 alias <ip>/32` (root-gated, run
//     inside the netd daemon boundary in deployment). Tests use the rootless
//     noopAliasManager, and the integration path binds a specific 127.0.0.x per
//     VIP — a faithful per-VIP source-identity rehearsal, since 127.0.0.0/8 is
//     entirely loopback on Darwin and bindable without an alias.
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
// # Locality
//
// Backend locality (local lo0 pod IP vs remote pod over the wireguard mesh) is
// computed proxy-side from the node podCIDR with a cheap netip.Prefix.Contains —
// no getifaddrs scan per connection. It is a hint/metric in M1 (steering does not
// depend on it); the mesh data path lands in M3.
//
// # UDP flow timeout (noted, not built in M1)
//
// The ClusterIP and NodePort listeners are protocol-aware (PortKey carries the
// netv1.Protocol, and network() maps it to "tcp"/"udp"), and 53/UDP is the
// motivating Service. A correct UDP Service proxy is connectionless: there is no
// Accept/CloseWrite, so the proxy must (a) read a datagram on the VIP socket, (b)
// pick a backend, (c) open (and cache) a per-flow upstream socket keyed by the
// client 5-tuple, (d) relay datagrams both ways, and (e) expire the flow after an
// idle timeout (Linux conntrack uses 30s for UDP; kube-proxy's userspace proxy
// used a comparable udpIdleTimeout) so cached sockets and the backend selection
// do not pin to a dead client. M1 ships the TCP data path end-to-end; the UDP
// datagram relay + idle-flow GC is deferred (it pairs with CoreDNS on 53/UDP and
// is tracked for the DNS milestone). The routing table — the part that decides
// which backend a 53/UDP query goes to — is already protocol-keyed and tested.
package proxy
