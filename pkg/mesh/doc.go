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

// Package mesh is k3sm's cross-node pod network: a wireguard mesh that routes
// (never NATs) pod IPs between nodes, the macOS-native analog of flannel's
// wireguard backend. Each node runs userspace wireguard (wireguard-go) over a
// root-created utun; peers, endpoints, and pod /24s come from the net.k3sm.io/v1
// MeshPeer CRD (k3sm.io/apis/net/v1), watched and reconciled continuously so a
// peer that roams or wakes onto a new endpoint reconverges without a restart.
//
// # Why the pure logic is separated from the privileged device
//
// Bringing the mesh up touches root-only state (creating a utun, installing
// kernel routes, loading a pf anchor), so those operations live behind the Device
// seam and run inside the netd daemon boundary in deployment. Everything that
// decides WHAT to program is pure and table-tested without privilege: the route
// set (RouteSet), the AllowedIPs==podCIDR equality check (AllowedIPsMatchCIDR),
// the wireguard UAPI config (Plan.UAPI), the public-key encoding (publicKeyHex),
// and the MTU/MSS constants. BuildPlan turns a MeshPeer snapshot into a Plan; the
// Device applies it.
//
// # Four load-bearing mechanics (each blackholes traffic if dropped)
//
//   - Per-peer kernel routes, distinct from wireguard AllowedIPs. wireguard-go is
//     the library over a raw utun; unlike wg-quick it installs NO kernel routes,
//     so the mesh adds one route per peer podCIDR -> utun itself (Device.Apply,
//     fed by RouteSet). RouteSet NEVER includes this node's own /24 or the
//     100.64.0.0/10 aggregate — routing either to the utun would steal same-node
//     lo0 loopback traffic. Two macOS facts make installing them a real step
//     rather than a formality, and dropping either one blackholes every peer while
//     the logs report success: the kernel refuses an interface-bound route on an
//     ADDRESSLESS utun (hence the mesh-link address, podnet.MeshLinkIP, on the
//     tunnel itself), and route(8) exits 0 even when that refusal happened (hence
//     the read-back: every apply verifies its routes against the kernel routing
//     table and fails loudly on divergence, routeTable/reconcileRoutes).
//   - A reserved mesh-egress source (podnet.MeshEgressIP, the .1 of the node /24),
//     which stays an lo0 alias and is never moved onto the utun.
//     The Service proxy binds its backend dialer to it (proxy.WithMeshEgressSource)
//     so a cross-node dial egresses the utun from an address inside this node's
//     AllowedIPs; wireguard drops a packet whose source no peer's AllowedIPs covers,
//     so a wrong/unscoped egress source is a one-way blackhole.
//   - The node /24 as a single source of truth. AllowedIPs == the podnet IPAM CIDR
//     == node.spec.podCIDR; the mesh asserts equality, not merely symmetry, because
//     a symmetric-but-wrong AllowedIPs still blackholes.
//   - An MSS clamp scoped to the utun egress. A pod socket bound to an lo0 alias
//     sees the loopback MTU (16384) and can advertise an MSS too large for the 1380
//     utun, blackholing large-payload cross-node TCP; a minimal pf scrub anchor
//     (pulled forward from M4) clamps max-mss on the utun only, never lo0.
//
// # The endpoint-roaming contract
//
// A peer's endpoint is owned by wireguard once that peer has been heard from: the
// handshake roams the endpoint to the real underlay source the peer's packets
// arrive from, which is authenticated ground truth, while the MeshPeer CR endpoint
// is only a hint for making first contact. So the reconcile programs the CR
// endpoint exactly three times — when the peer is new to the device, when its
// public key changed, and when the operator changed the CR endpoint itself — and
// otherwise leaves it alone (Plan.UAPIUpdate), because re-stamping a stale CR
// endpoint over a roamed one blackholes every reply until the peer re-handshakes.
//
// # Scope (M3.1)
//
// No relay: endpoints must be mutually routable / same-L2 (the MeshPeer carries a
// reachable host:port). Cross-node source identity is per-NODE, not per-pod (the
// egress source is the node's mesh IP). NodePort (M3.2) and the infra-VIP mesh
// exemption (M3.3) are separate sub-phases. Private keys never leave the node and
// never appear on a MeshPeer (DESIGN §5b).
package mesh
