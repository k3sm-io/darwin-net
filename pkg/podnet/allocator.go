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
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
)

// ClusterPodCIDR is k3sm's default cluster pod CIDR: 100.64.0.0/10 (the RFC 6598
// shared address space, as in DESIGN.md §5b). Each node carves a unique /24 out
// of it by node index, giving up to 2^14 nodes of 254 usable pod IPs each; the
// unique-per-node /24 is what lets the wireguard mesh route (not NAT) pod IPs in
// M3. It is exposed so callers that do not override the CIDR get the canonical
// default.
var ClusterPodCIDR = netip.MustParsePrefix("100.64.0.0/10")

// nodeCIDRBits is the prefix length of a per-node pod CIDR. A /24 yields 254
// usable host addresses (the network and broadcast addresses are reserved), which
// bounds how many pods a single node can run — matching the per-node /24 carve in
// DESIGN.md §5b and the proxy's locality classification.
const nodeCIDRBits = 24

// Sentinel errors returned by the Allocator. Compare with errors.Is, never by
// string match.
var (
	// ErrPoolExhausted is returned by Allocate when every usable host address in
	// the node /24 is already allocated.
	ErrPoolExhausted = errors.New("podnet: pod IP pool exhausted")
	// ErrNotAllocated is returned by Release when the address was not handed out by
	// this allocator (so there is nothing to free). It is informational: Release of
	// an unknown address is otherwise tolerated by the leak-free teardown path.
	ErrNotAllocated = errors.New("podnet: address not allocated")
	// ErrOutOfRange is returned when an address is not inside this node's /24.
	ErrOutOfRange = errors.New("podnet: address not in node CIDR")
)

// NodeCIDR derives a node's per-node pod CIDR (a /24) from the cluster pod CIDR
// and a zero-based node index. The carve is deterministic — the same index always
// yields the same /24 — so a node's pod CIDR is stable across a daemon restart
// without persisting it, and distinct indices never collide (each /24 is disjoint).
// It returns ErrOutOfRange if index is negative or exceeds the number of /24s the
// cluster CIDR can hold.
//
// Example: NodeCIDR(100.64.0.0/10, 0) == 100.64.0.0/24; index 1 == 100.64.1.0/24.
func NodeCIDR(clusterCIDR netip.Prefix, index int) (netip.Prefix, error) {
	if !clusterCIDR.IsValid() {
		return netip.Prefix{}, fmt.Errorf("%w: invalid cluster CIDR", ErrOutOfRange)
	}
	clusterCIDR = clusterCIDR.Masked()
	if clusterCIDR.Addr().Is6() {
		return netip.Prefix{}, fmt.Errorf("%w: only IPv4 cluster CIDRs are supported", ErrOutOfRange)
	}
	if clusterCIDR.Bits() > nodeCIDRBits {
		return netip.Prefix{}, fmt.Errorf("%w: cluster CIDR /%d is smaller than a node /%d", ErrOutOfRange, clusterCIDR.Bits(), nodeCIDRBits)
	}
	if index < 0 {
		return netip.Prefix{}, fmt.Errorf("%w: negative node index %d", ErrOutOfRange, index)
	}
	// Number of /24s the cluster CIDR contains (e.g. /10 holds 2^(24-10) = 16384).
	maxNodes := 1 << (nodeCIDRBits - clusterCIDR.Bits())
	if index >= maxNodes {
		return netip.Prefix{}, fmt.Errorf("%w: node index %d exceeds %d /%d blocks in %s", ErrOutOfRange, index, maxNodes, nodeCIDRBits, clusterCIDR)
	}

	base := clusterCIDR.Addr().As4()
	// The /24 base is the cluster base with `index` added in the third-octet space.
	// Shift index into the byte boundary above the /24 host space (8 bits) and add.
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	v += uint32(index) << (32 - nodeCIDRBits)
	a4 := [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	return netip.PrefixFrom(netip.AddrFrom4(a4), nodeCIDRBits), nil
}

// Allocator hands out unique host /32 addresses from a single node's pod CIDR (a
// /24). It is the pure-logic IPAM core: no interface, no syscalls, no privilege,
// so its allocate/release behavior is fully table-tested. Three addresses in the
// /24 are reserved and never handed out: the network address (.0), the broadcast
// address (.255), and the mesh-egress /32 (.1, see MeshEgressIP) the wireguard
// mesh uses as this node's tunnel-egress source. A /24 therefore yields 253 usable
// pod addresses (.2 through .254).
//
// Locking discipline: all state is guarded by mu. Allocate and Release take the
// write lock; the read-only accessors take the read lock. The allocator is safe
// for concurrent use by the pod setup/teardown paths.
type Allocator struct {
	cidr netip.Prefix
	// meshEgress is the .1 /32 reserved as the node's wireguard mesh-egress source
	// (MeshEgressIP); it is excluded from the usable range so it is never handed to
	// a pod (a pod IP colliding with the mesh source would break mesh return paths).
	meshEgress netip.Addr
	// first and last bound the usable host range [first, last] inside the /24
	// (network, mesh-egress, and broadcast excluded). next is the rotating cursor
	// Allocate scans from so freed-then-reallocated addresses are reused without bias.
	first, last netip.Addr
	next        netip.Addr

	mu        sync.Mutex
	allocated map[netip.Addr]struct{}
}

// NewAllocator returns an Allocator over the given node CIDR, which must be a
// valid IPv4 /24 (use NodeCIDR to derive one). It returns an error if the CIDR is
// invalid or not a /24, so a misconfigured node fails fast rather than handing out
// addresses from the wrong block.
func NewAllocator(nodeCIDR netip.Prefix) (*Allocator, error) {
	if !nodeCIDR.IsValid() {
		return nil, fmt.Errorf("%w: invalid node CIDR", ErrOutOfRange)
	}
	if nodeCIDR.Addr().Is6() {
		return nil, fmt.Errorf("%w: node CIDR must be IPv4", ErrOutOfRange)
	}
	if nodeCIDR.Bits() != nodeCIDRBits {
		return nil, fmt.Errorf("%w: node CIDR must be a /%d, got /%d", ErrOutOfRange, nodeCIDRBits, nodeCIDR.Bits())
	}
	nodeCIDR = nodeCIDR.Masked()
	network := nodeCIDR.Addr()
	meshEgress := network.Next()       // .1 — reserved as the node's mesh-egress /32 (MeshEgressIP)
	first := meshEgress.Next()         // .2 — first usable pod IP (.0 network + .1 mesh-egress reserved)
	last := lastHostInSlash24(network) // .254 — skip the .255 broadcast address
	return &Allocator{
		cidr:       nodeCIDR,
		meshEgress: meshEgress,
		first:      first,
		last:       last,
		next:       first,
		allocated:  make(map[netip.Addr]struct{}),
	}, nil
}

// CIDR returns the node /24 this allocator serves.
func (a *Allocator) CIDR() netip.Prefix { return a.cidr }

// MeshEgressIP returns the /32 (.1 of the node /24) this allocator reserves as the
// node's wireguard mesh-egress source. It is never handed out by Allocate; see the
// package-level MeshEgressIP for the canonical derivation the mesh and proxy share.
func (a *Allocator) MeshEgressIP() netip.Addr { return a.meshEgress }

// Allocate reserves and returns the next free host address in the node /24. It
// scans forward from a rotating cursor, wrapping at the broadcast boundary, so a
// released address is eventually reused and no address is ever handed out twice.
// It returns ErrPoolExhausted when every usable host is allocated.
func (a *Allocator) Allocate() (netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Scan the whole usable range once starting at the cursor.
	candidate := a.next
	for i := 0; i < a.usableCount(); i++ {
		if !candidate.IsValid() || candidate.Compare(a.last) > 0 {
			candidate = a.first // wrap past the broadcast address
		}
		if _, taken := a.allocated[candidate]; !taken {
			a.allocated[candidate] = struct{}{}
			a.next = candidate.Next()
			return candidate, nil
		}
		candidate = candidate.Next()
	}
	return netip.Addr{}, ErrPoolExhausted
}

// AllocateSpecific reserves a caller-chosen address (e.g. when reattaching to a
// pod whose IP is already recorded in PodBox.pod_ip after a restart). It returns
// ErrOutOfRange if ip is not a usable host in the node /24, and a wrapped
// ErrPoolExhausted-free success only if ip was free; if ip is already allocated it
// returns true for alreadyHeld so an idempotent re-Setup can distinguish a no-op
// from a fresh reservation.
func (a *Allocator) AllocateSpecific(ip netip.Addr) (alreadyHeld bool, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.inHostRange(ip) {
		return false, fmt.Errorf("%w: %s not a host in %s", ErrOutOfRange, ip, a.cidr)
	}
	if _, taken := a.allocated[ip]; taken {
		return true, nil
	}
	a.allocated[ip] = struct{}{}
	return false, nil
}

// Release frees a previously allocated address so it can be reused. It is
// idempotent for the leak-free teardown path: releasing an address this allocator
// never handed out returns ErrNotAllocated (which the PodNetwork teardown tolerates
// as already-gone) and leaves state unchanged. Releasing twice is a no-op after the
// first.
func (a *Allocator) Release(ip netip.Addr) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.allocated[ip]; !ok {
		return fmt.Errorf("%w: %s", ErrNotAllocated, ip)
	}
	delete(a.allocated, ip)
	return nil
}

// Allocated reports whether ip is currently held by this allocator.
func (a *Allocator) Allocated(ip netip.Addr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.allocated[ip]
	return ok
}

// InUse returns the number of currently allocated addresses.
func (a *Allocator) InUse() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.allocated)
}

// Capacity returns the number of usable host addresses in the node /24 (253 for a
// /24: 256 minus the network, broadcast, and mesh-egress reserved addresses).
func (a *Allocator) Capacity() int {
	return a.usableCount()
}

// Snapshot returns the currently allocated addresses in sorted order. It is used
// by tests and diagnostics; the returned slice is owned by the caller.
func (a *Allocator) Snapshot() []netip.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]netip.Addr, 0, len(a.allocated))
	for ip := range a.allocated {
		out = append(out, ip)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	return out
}

// usableCount is the count of host addresses in [first, last] inclusive.
func (a *Allocator) usableCount() int {
	f := a.first.As4()
	l := a.last.As4()
	fv := uint32(f[0])<<24 | uint32(f[1])<<16 | uint32(f[2])<<8 | uint32(f[3])
	lv := uint32(l[0])<<24 | uint32(l[1])<<16 | uint32(l[2])<<8 | uint32(l[3])
	return int(lv-fv) + 1
}

// inHostRange reports whether ip is a usable host address in the node /24
// (inside the CIDR and neither the network nor the broadcast address).
func (a *Allocator) inHostRange(ip netip.Addr) bool {
	if !ip.Is4() || !a.cidr.Contains(ip) {
		return false
	}
	return ip.Compare(a.first) >= 0 && ip.Compare(a.last) <= 0
}

// lastHostInSlash24 returns the broadcast-minus-one (.254) address of the /24
// whose network address is network.
func lastHostInSlash24(network netip.Addr) netip.Addr {
	b := network.As4()
	b[3] = 254
	return netip.AddrFrom4(b)
}
