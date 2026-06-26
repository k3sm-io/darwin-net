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
