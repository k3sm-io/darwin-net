package podnet

import (
	"errors"
	"net/netip"
	"testing"
)

// TestNodeCIDRCarveCollisionFree maps to acceptance M2.1-a1 (the per-node /24
// carve is collision-free): distinct node indices yield disjoint /24s out of the
// cluster CIDR, and out-of-range indices fail fast. Table-driven over the cluster
// default 100.64.0.0/10.
func TestNodeCIDRCarveCollisionFree(t *testing.T) {
	cases := []struct {
		name    string
		cluster netip.Prefix
		index   int
		want    string // expected /24, empty if an error is expected
		wantErr error
	}{
		{name: "index0", cluster: ClusterPodCIDR, index: 0, want: "100.64.0.0/24"},
		{name: "index1", cluster: ClusterPodCIDR, index: 1, want: "100.64.1.0/24"},
		{name: "index255", cluster: ClusterPodCIDR, index: 255, want: "100.64.255.0/24"},
		{name: "index256_wraps_third_octet", cluster: ClusterPodCIDR, index: 256, want: "100.65.0.0/24"},
		{name: "lastBlock", cluster: ClusterPodCIDR, index: (1 << 14) - 1, want: "100.127.255.0/24"},
		{name: "negativeIndex", cluster: ClusterPodCIDR, index: -1, wantErr: ErrOutOfRange},
		{name: "indexTooLarge", cluster: ClusterPodCIDR, index: 1 << 14, wantErr: ErrOutOfRange},
		{name: "clusterSmallerThanNode", cluster: netip.MustParsePrefix("100.64.0.0/25"), index: 0, wantErr: ErrOutOfRange},
		{name: "ipv6Cluster", cluster: netip.MustParsePrefix("fd00::/10"), index: 0, wantErr: ErrOutOfRange},
		{name: "exactSlash24Cluster", cluster: netip.MustParsePrefix("10.0.5.0/24"), index: 0, want: "10.0.5.0/24"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NodeCIDR(tc.cluster, tc.index)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("NodeCIDR(%s, %d) err = %v, want %v", tc.cluster, tc.index, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NodeCIDR(%s, %d) unexpected err: %v", tc.cluster, tc.index, err)
			}
			if got.String() != tc.want {
				t.Fatalf("NodeCIDR(%s, %d) = %s, want %s", tc.cluster, tc.index, got, tc.want)
			}
		})
	}

	// Disjointness: a sweep of indices must produce pairwise non-overlapping /24s.
	seen := make(map[netip.Prefix]int)
	for i := 0; i < 512; i++ {
		p, err := NodeCIDR(ClusterPodCIDR, i)
		if err != nil {
			t.Fatalf("NodeCIDR index %d: %v", i, err)
		}
		if prev, dup := seen[p]; dup {
			t.Fatalf("index %d and %d both carved %s — collision", i, prev, p)
		}
		seen[p] = i
	}
}

// TestNodeCIDRStableAcrossRestart maps to acceptance M2.1-a1 (the per-node /24 is
// stable across restart): the same node index always derives the same /24, so a
// daemon restart re-derives the identical block without persisting it.
func TestNodeCIDRStableAcrossRestart(t *testing.T) {
	const index = 42
	first, err := NodeCIDR(ClusterPodCIDR, index)
	if err != nil {
		t.Fatalf("first derive: %v", err)
	}
	// A "restart" is just deriving again from the same inputs.
	second, err := NodeCIDR(ClusterPodCIDR, index)
	if err != nil {
		t.Fatalf("second derive: %v", err)
	}
	if first != second {
		t.Fatalf("node CIDR not stable: %s != %s", first, second)
	}
	if first.String() != "100.64.42.0/24" {
		t.Fatalf("unexpected /24 for index %d: %s", index, first)
	}
}

// TestAllocatorUniqueNoDoubleAllocation maps to acceptance M2.1-a1 (allocate
// unique IPs from the CIDR; no double-allocation): draining the pool yields every
// usable host exactly once, all inside the /24 and excluding network/broadcast,
// then the pool is exhausted.
func TestAllocatorUniqueNoDoubleAllocation(t *testing.T) {
	cidr := netip.MustParsePrefix("100.64.7.0/24")
	a, err := NewAllocator(cidr)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if got := a.Capacity(); got != 254 {
		t.Fatalf("Capacity = %d, want 254", got)
	}

	network := netip.MustParseAddr("100.64.7.0")
	broadcast := netip.MustParseAddr("100.64.7.255")

	seen := make(map[netip.Addr]bool)
	for i := 0; i < 254; i++ {
		ip, err := a.Allocate()
		if err != nil {
			t.Fatalf("Allocate #%d: %v", i, err)
		}
		if seen[ip] {
			t.Fatalf("Allocate handed out %s twice — double allocation", ip)
		}
		seen[ip] = true
		if !cidr.Contains(ip) {
			t.Fatalf("Allocate handed out %s outside %s", ip, cidr)
		}
		if ip == network || ip == broadcast {
			t.Fatalf("Allocate handed out reserved address %s", ip)
		}
	}
	if got := a.InUse(); got != 254 {
		t.Fatalf("InUse = %d, want 254", got)
	}
	if _, err := a.Allocate(); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("Allocate on full pool err = %v, want ErrPoolExhausted", err)
	}
}

// TestAllocatorReleaseLeakFree maps to acceptance M2.1-a1 (release is leak-free):
// after a full drain, releasing every address returns the pool to empty and the
// addresses are reusable; releasing an address twice or one never allocated is the
// tolerated no-op the leak-free teardown relies on.
func TestAllocatorReleaseLeakFree(t *testing.T) {
	a, err := NewAllocator(netip.MustParsePrefix("100.64.3.0/24"))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	var held []netip.Addr
	for i := 0; i < 254; i++ {
		ip, err := a.Allocate()
		if err != nil {
			t.Fatalf("Allocate #%d: %v", i, err)
		}
		held = append(held, ip)
	}
	for _, ip := range held {
		if err := a.Release(ip); err != nil {
			t.Fatalf("Release %s: %v", ip, err)
		}
	}
	if got := a.InUse(); got != 0 {
		t.Fatalf("InUse after full release = %d, want 0 — leak", got)
	}

	// Releasing again is a no-op error (tolerated by teardown), state unchanged.
	if err := a.Release(held[0]); !errors.Is(err, ErrNotAllocated) {
		t.Fatalf("double Release err = %v, want ErrNotAllocated", err)
	}
	if got := a.InUse(); got != 0 {
		t.Fatalf("InUse mutated by no-op Release = %d, want 0", got)
	}

	// Releasing an address never handed out is ErrNotAllocated, not a panic.
	never := netip.MustParseAddr("100.64.3.200")
	if err := a.Release(never); !errors.Is(err, ErrNotAllocated) {
		t.Fatalf("Release of unallocated %s err = %v, want ErrNotAllocated", never, err)
	}

	// The whole pool is reusable after release.
	for i := 0; i < 254; i++ {
		if _, err := a.Allocate(); err != nil {
			t.Fatalf("re-Allocate #%d after release: %v", i, err)
		}
	}
	if got := a.InUse(); got != 254 {
		t.Fatalf("InUse after refill = %d, want 254", got)
	}
}

// TestAllocatorChurnLeakFree maps to acceptance M2.1-a1 (leak-free + idempotent
// under churn): many allocate/release cycles must never grow the in-use set beyond
// what is held and must return to empty when everything is released.
func TestAllocatorChurnLeakFree(t *testing.T) {
	a, err := NewAllocator(netip.MustParsePrefix("100.64.9.0/24"))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	for cycle := 0; cycle < 200; cycle++ {
		ips := make([]netip.Addr, 0, 16)
		for i := 0; i < 16; i++ {
			ip, err := a.Allocate()
			if err != nil {
				t.Fatalf("cycle %d Allocate #%d: %v", cycle, i, err)
			}
			ips = append(ips, ip)
		}
		if got := a.InUse(); got != 16 {
			t.Fatalf("cycle %d InUse = %d, want 16", cycle, got)
		}
		for _, ip := range ips {
			if err := a.Release(ip); err != nil {
				t.Fatalf("cycle %d Release %s: %v", cycle, ip, err)
			}
		}
		if got := a.InUse(); got != 0 {
			t.Fatalf("cycle %d InUse after release = %d, want 0 — leak", cycle, got)
		}
	}
}

// TestAllocateSpecific covers the restart-reattach path: a recorded pod IP can be
// re-claimed (idempotently), an already-held address reports alreadyHeld, and an
// out-of-range address is rejected.
func TestAllocateSpecific(t *testing.T) {
	cidr := netip.MustParsePrefix("100.64.5.0/24")
	a, err := NewAllocator(cidr)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	want := netip.MustParseAddr("100.64.5.17")
	held, err := a.AllocateSpecific(want)
	if err != nil {
		t.Fatalf("AllocateSpecific(%s): %v", want, err)
	}
	if held {
		t.Fatalf("AllocateSpecific(%s) reported alreadyHeld on first claim", want)
	}
	if !a.Allocated(want) {
		t.Fatalf("%s not marked allocated", want)
	}

	// Re-claim is idempotent and reports alreadyHeld.
	held, err = a.AllocateSpecific(want)
	if err != nil {
		t.Fatalf("re-AllocateSpecific(%s): %v", want, err)
	}
	if !held {
		t.Fatalf("re-AllocateSpecific(%s) did not report alreadyHeld", want)
	}
	if got := a.InUse(); got != 1 {
		t.Fatalf("InUse = %d, want 1 after idempotent re-claim", got)
	}

	for _, bad := range []netip.Addr{
		netip.MustParseAddr("100.64.5.0"),   // network
		netip.MustParseAddr("100.64.5.255"), // broadcast
		netip.MustParseAddr("10.0.0.1"),     // outside CIDR
	} {
		if _, err := a.AllocateSpecific(bad); !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("AllocateSpecific(%s) err = %v, want ErrOutOfRange", bad, err)
		}
	}
}

// TestNewAllocatorRejectsNonSlash24 fails fast on a misconfigured node CIDR so the
// allocator never hands out addresses from the wrong-size block.
func TestNewAllocatorRejectsNonSlash24(t *testing.T) {
	for _, bad := range []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/25"),
		netip.MustParsePrefix("fd00::/24"),
		{},
	} {
		if _, err := NewAllocator(bad); !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("NewAllocator(%s) err = %v, want ErrOutOfRange", bad, err)
		}
	}
}
