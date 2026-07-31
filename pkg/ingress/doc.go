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

// Package ingress is k3sm's L7 HTTP(S) datapath (M10.3): an in-process userspace
// reverse proxy fronting the ClusterIP VIPs the L4 Service proxy (pkg/proxy)
// already owns. It is deliberately its OWN package — the L4 splice and the L7
// router are distinct concerns — and it deliberately dials Service ClusterIP
// VIPs, never pod IPs: the two-hop path keeps EndpointSlice tracking, session
// affinity, and mesh-egress source discipline in the L4 proxy where they live.
//
// # Layers (mirroring the proxy's pure-core / socket-layer split)
//
//   - RouteTable (route.go) is the pure routing core: host+path rules in,
//     Backend (VIP:port) out. Exact hosts only (wildcard hosts are DEFERRED);
//     PathType Exact | Prefix with element-wise segment matching, longest match
//     wins, Exact beats Prefix at equal path; ImplementationSpecific is treated
//     as Prefix. No match falls to the table's default backend, else a
//     router-level 404. It holds no HTTP server types and swaps its rule
//     snapshot atomically.
//   - CertStore / CertResolver (tls.go) is the SNI-keyed TLS termination seam:
//     an atomically-swapped host->certificate map behind
//     tls.Config.GetCertificate. Keys and certificates live IN PROCESS MEMORY
//     ONLY — never written to any path — and a bad or missing certificate fails
//     only that host's handshake (unknown SNI closes the handshake; no default
//     certificate is invented). NextProtos is pinned to http/1.1.
//   - handler (handler.go) is the stdlib httputil.ReverseProxy datapath with
//     strict forwarded-header discipline: X-Forwarded-For is OVERWRITTEN with
//     the peer (never appended), inbound Forwarded / X-Real-IP are stripped, and
//     the inbound Host is preserved for backend virtual hosting. A down backend
//     returns 502 with a throttled Warn.
//   - Server (server.go) is the socket layer: it binds the node address the
//     HOST chose — the wildcard included, though the netd daemon still refuses
//     a wildcard bind, so helper mode is specific-address only (see
//     Config.Addr) — through the shared pkg/netbind seam, serves HTTP and TLS
//     listeners, and drains gracefully on context cancel.
//   - Watcher (watch.go) converts class-filtered networking/v1 Ingress objects
//     (plus referenced Services, for the ClusterIP VIP and port-by-name
//     resolution) into RouteTable rules, and surfaces tls[] Secret references to
//     the host via a callback — this package never holds a Secrets client.
package ingress
