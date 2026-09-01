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

package podnet

import (
	"fmt"
	"net/netip"
)

// MeshEgressIP returns the /32 reserved from a node's pod /24 as that node's
// wireguard mesh-egress source address: the first host (.1) of nodeCIDR. The
// derivation is the single source of truth shared by three consumers — the
// Allocator (which excludes it so it is never handed to a pod), the wireguard
// mesh (which assigns it as the node's tunnel-egress source), and the Service
// proxy (which binds the backend dialer's LocalAddr to it). Binding the egress
// source matters because wireguard accepts an inbound packet only when its source
// falls within some peer's AllowedIPs (= the sending node's podCIDR); a dial that
// egresses the mesh from a wrong or unscoped source is silently dropped on the
// return path (a one-way blackhole). Because the address is derived from the node
// podCIDR it is inside that node's AllowedIPs by construction.
//
// nodeCIDR must be an IPv4 /24 (use NodeCIDR to derive one); MeshEgressIP returns
// ErrOutOfRange otherwise so a misconfigured node fails fast rather than reserving
// an address from the wrong block.
func MeshEgressIP(nodeCIDR netip.Prefix) (netip.Addr, error) {
	if !nodeCIDR.IsValid() {
		return netip.Addr{}, fmt.Errorf("%w: invalid node CIDR", ErrOutOfRange)
	}
	if !nodeCIDR.Addr().Is4() {
		return netip.Addr{}, fmt.Errorf("%w: node CIDR must be IPv4", ErrOutOfRange)
	}
	if nodeCIDR.Bits() != nodeCIDRBits {
		return netip.Addr{}, fmt.Errorf("%w: node CIDR must be a /%d, got /%d", ErrOutOfRange, nodeCIDRBits, nodeCIDR.Bits())
	}
	return nodeCIDR.Masked().Addr().Next(), nil
}

// MeshLinkIP returns the /32 the node's wireguard utun carries as its OWN
// point-to-point interface address: the last address of nodeCIDR (.255), which the
// Allocator already reserves as the broadcast address and so never hands to a pod.
// Reusing that reservation is deliberate — it keeps the usable pod range at 253
// addresses, and a /32 point-to-point interface address has no subnet-broadcast
// semantics (no interface in the datapath is IFF_BROADCAST: lo0 is a loopback and
// the utun is point-to-point).
//
// It exists because macOS will not install an interface-bound route on an
// ADDRESSLESS utun: the kernel resolves such a route's source address from an
// address on that interface and rejects RTM_ADD with ENETUNREACH when there is
// none. Giving the utun an address of its own is what makes the per-peer routes
// installable at all. Because it is derived from the node podCIDR it is inside that
// node's AllowedIPs by construction, so host traffic the kernel sources from it
// (an unbound dial to a peer pod IP, an ICMP error toward a peer) is accepted by
// the receiving node rather than dropped by cryptokey routing.
//
// It is deliberately NOT the mesh-egress source (MeshEgressIP), and the two must
// never be collapsed: an address that lives on the utun is REACHED over the utun,
// so assigning the mesh IP there installs a host route for it through the tunnel
// and a same-node dial of the node's own mesh IP is encrypted and dropped instead
// of looping back. The mesh IP stays an lo0 alias — locally bindable and
// loopback-reachable — and inbound tunnel packets addressed to it are still
// delivered and answered, because macOS accepts a packet for any local address
// whichever interface it arrives on.
//
// nodeCIDR must be an IPv4 /24 (use NodeCIDR to derive one); MeshLinkIP returns
// ErrOutOfRange otherwise.
func MeshLinkIP(nodeCIDR netip.Prefix) (netip.Addr, error) {
	if !nodeCIDR.IsValid() {
		return netip.Addr{}, fmt.Errorf("%w: invalid node CIDR", ErrOutOfRange)
	}
	if !nodeCIDR.Addr().Is4() {
		return netip.Addr{}, fmt.Errorf("%w: node CIDR must be IPv4", ErrOutOfRange)
	}
	if nodeCIDR.Bits() != nodeCIDRBits {
		return netip.Addr{}, fmt.Errorf("%w: node CIDR must be a /%d, got /%d", ErrOutOfRange, nodeCIDRBits, nodeCIDR.Bits())
	}
	return broadcastInSlash24(nodeCIDR.Masked().Addr()), nil
}
