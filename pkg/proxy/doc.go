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
//     Ready backends, with a deterministic round-robin picker (Pick) and an
//     explicit-index picker (PickAt) for table-assertable distribution. Only
//     Ready endpoints are ever admitted (SetEndpoints filters at the single
//     admission point), so an unready endpoint can never be selected. It carries
//     no sockets and no client-go types, so its behavior is fully unit-tested.
//     SessionAffinity is intentionally out of scope for M1: this is round-robin
//     only.
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
// that L4-load-balances to the SAME Ready backend set as the ClusterIP. The
// NodePort listener is bound IN-PROCESS (a plain net.Listen on the wildcard); it
// never goes through the root netd helper, which binds only specific-address ports
// and rejects the wildcard — a >=1024 wildcard needs no privilege, so there is no
// helper NodePort path. This is
// externalTrafficPolicy: Cluster — externalTrafficPolicy: Local is NOT honored,
// because the userspace splice opens a fresh backend connection and so does not
// preserve the external client's source IP (the precondition Local relies on).
// NodePort is TCP only; the UDP NodePort relay is deferred together with the UDP
// datagram relay below (a UDP port opens no datagram socket on either the
// ClusterIP or the NodePort). stockkitty's NodePort surface (VSCode SSH :22, the
// snapshot gRPC range) is all TCP, so UDP NodePort is not claimed until the relay
// lands.
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
// datagram relay + idle-flow GC is deferred (it pairs with the per-node resolver
// on 53/UDP and is tracked for the DNS milestone — docs/BACKLOG.md B23). The routing table — the part that decides
// which backend a 53/UDP query goes to — is already protocol-keyed and tested.
package proxy
