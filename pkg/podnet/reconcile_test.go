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
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
)

// TestReattachPodRoundTrip is the M10.1 crash-reconcile gate (reattach half):
// a restarted daemon re-adopts a known podID->IP binding, a subsequent Setup
// for the same pod returns the same address without a fresh allocation, and no
// other pod can be handed that address.
func TestReattachPodRoundTrip(t *testing.T) {
	n, fake := newTestNetwork(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("100.64.0.10")

	if err := n.ReattachPod(ctx, "pod-a", ip); err != nil {
		t.Fatalf("ReattachPod: %v", err)
	}
	if got := fake.ensures(ip); got != 1 {
		t.Fatalf("Ensure called %d times for %s, want 1 (idempotent re-adoption)", got, ip)
	}
	if got, ok := n.IP("pod-a"); !ok || got != ip {
		t.Fatalf("IP(pod-a) = %s,%v after reattach, want %s,true", got, ok, ip)
	}

	// A subsequent Setup for the same pod is the idempotent path: same IP, no
	// second allocation.
	got, err := n.Setup(ctx, "pod-a")
	if err != nil {
		t.Fatalf("Setup after reattach: %v", err)
	}
	if got != ip {
		t.Fatalf("Setup after reattach = %s, want the reattached %s", got, ip)
	}
	if in := n.alloc.InUse(); in != 1 {
		t.Fatalf("InUse = %d after reattach+Setup, want 1", in)
	}

	// A different pod can never be allocated the reattached address.
	other, err := n.Setup(ctx, "pod-b")
	if err != nil {
		t.Fatalf("Setup pod-b: %v", err)
	}
	if other == ip {
		t.Fatalf("pod-b was handed the reattached address %s", ip)
	}
	if err := n.ReattachPod(ctx, "pod-c", ip); !errors.Is(err, ErrIPInUse) {
		t.Fatalf("ReattachPod(pod-c, %s) err = %v, want ErrIPInUse", ip, err)
	}

	// Reattach is idempotent for the same binding, and refuses a rebind.
	if err := n.ReattachPod(ctx, "pod-a", ip); err != nil {
		t.Fatalf("idempotent ReattachPod: %v", err)
	}
	if err := n.ReattachPod(ctx, "pod-a", netip.MustParseAddr("100.64.0.99")); err == nil {
		t.Fatal("ReattachPod rebound pod-a to a different address")
	}
}

// TestReattachPodRejects proves reattach validates its inputs: an empty pod id,
// an out-of-CIDR address, and the reserved mesh-egress /32 all fail fast with
// the right sentinel, and a failed alias plumb rolls the reservation back.
func TestReattachPodRejects(t *testing.T) {
	ctx := context.Background()

	t.Run("empty pod id", func(t *testing.T) {
		n, _ := newTestNetwork(t)
		if err := n.ReattachPod(ctx, "", netip.MustParseAddr("100.64.0.10")); !errors.Is(err, ErrEmptyPodID) {
			t.Fatalf("err = %v, want ErrEmptyPodID", err)
		}
	})
	t.Run("address outside the node CIDR", func(t *testing.T) {
		n, _ := newTestNetwork(t)
		if err := n.ReattachPod(ctx, "pod-a", netip.MustParseAddr("100.64.9.10")); !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("err = %v, want ErrOutOfRange", err)
		}
	})
	t.Run("reserved mesh-egress address", func(t *testing.T) {
		n, _ := newTestNetwork(t)
		if err := n.ReattachPod(ctx, "pod-a", n.alloc.MeshEgressIP()); !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("err = %v, want ErrOutOfRange (reserved address must stay reserved)", err)
		}
	})
	t.Run("failed alias plumb rolls back the reservation", func(t *testing.T) {
		n, err := New(netip.MustParsePrefix("100.64.0.0/24"), withAliasManager(&failingAliasManager{}))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ip := netip.MustParseAddr("100.64.0.10")
		if err := n.ReattachPod(ctx, "pod-a", ip); err == nil {
			t.Fatal("ReattachPod succeeded despite alias failure")
		}
		if n.alloc.Allocated(ip) {
			t.Fatalf("%s still reserved after failed reattach — leak", ip)
		}
		if got := n.Pods(); got != 0 {
			t.Fatalf("Pods = %d after failed reattach, want 0", got)
		}
	})
}

// TestSweepStaleRemovesExactlyOrphans is the M10.1 crash-reconcile gate (sweep
// half): with orphaned aliases left on lo0 by a crashed previous daemon, the
// sweep removes exactly the orphans — the known (reattached) pod's alias
// survives and the reserved mesh-egress address is never touched.
func TestSweepStaleRemovesExactlyOrphans(t *testing.T) {
	n, fake := newTestNetwork(t)
	ctx := context.Background()

	knownIP := netip.MustParseAddr("100.64.0.10")
	orphanA := netip.MustParseAddr("100.64.0.20")
	orphanB := netip.MustParseAddr("100.64.0.30")

	// Simulate the crashed previous daemon: aliases exist on the "kernel" (the
	// fake) for a still-running pod and for two pods that died with it.
	for _, ip := range []netip.Addr{knownIP, orphanA, orphanB} {
		if err := fake.Ensure(ctx, ip); err != nil {
			t.Fatalf("seed alias %s: %v", ip, err)
		}
	}

	// The startup reconcile: reattach the still-running pod, then sweep.
	if err := n.ReattachPod(ctx, "pod-a", knownIP); err != nil {
		t.Fatalf("ReattachPod: %v", err)
	}
	known := map[string]netip.Addr{"pod-a": knownIP}
	if err := n.SweepStale(ctx, known); err != nil {
		t.Fatalf("SweepStale: %v", err)
	}

	if got := fake.removes(knownIP); got != 0 {
		t.Fatalf("known pod alias %s was removed %d times — sweep must keep it", knownIP, got)
	}
	if got := fake.removes(n.alloc.MeshEgressIP()); got != 0 {
		t.Fatalf("reserved mesh-egress %s was removed %d times — sweep must never touch it", n.alloc.MeshEgressIP(), got)
	}
	for _, orphan := range []netip.Addr{orphanA, orphanB} {
		if got := fake.removes(orphan); got == 0 {
			t.Fatalf("orphan alias %s was not swept", orphan)
		}
	}
	// Exactly the known pod's alias remains live.
	if got := fake.liveAliases(); got != 1 {
		t.Fatalf("liveAliases = %d after sweep, want 1 (the known pod)", got)
	}
	// And the reattached pod still serves: Setup returns its address.
	if got, err := n.Setup(ctx, "pod-a"); err != nil || got != knownIP {
		t.Fatalf("Setup after sweep = %s,%v, want %s,nil", got, err, knownIP)
	}
}

// TestSweepStaleEmptyNodeNoOp proves both helpers are safe pre-serve on an
// empty node: a nil known set sweeps nothing live, returns no error, and the
// network then serves Setup normally.
func TestSweepStaleEmptyNodeNoOp(t *testing.T) {
	n, fake := newTestNetwork(t)
	ctx := context.Background()

	if err := n.SweepStale(ctx, nil); err != nil {
		t.Fatalf("SweepStale on an empty node: %v", err)
	}
	if got := fake.liveAliases(); got != 0 {
		t.Fatalf("liveAliases = %d after empty sweep, want 0", got)
	}
	if _, err := n.Setup(ctx, "pod-a"); err != nil {
		t.Fatalf("Setup after empty sweep: %v", err)
	}
}

// TestSweepStaleCollectsErrors proves a failing removal is skipped and
// collected — one stuck alias does not strand the rest of the sweep — and the
// joined error surfaces every failure.
func TestSweepStaleCollectsErrors(t *testing.T) {
	stuck := netip.MustParseAddr("100.64.0.20")
	fake := &stuckRemoveAliasManager{fakeAliasManager: newFakeAliasManager(), stuck: stuck}
	n, err := New(netip.MustParsePrefix("100.64.0.0/24"), withAliasManager(fake))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	orphan := netip.MustParseAddr("100.64.0.30")
	for _, ip := range []netip.Addr{stuck, orphan} {
		if err := fake.Ensure(ctx, ip); err != nil {
			t.Fatalf("seed alias %s: %v", ip, err)
		}
	}

	err = n.SweepStale(ctx, nil)
	if err == nil {
		t.Fatal("SweepStale returned nil despite a stuck alias")
	}
	if got := fake.removes(orphan); got == 0 {
		t.Fatalf("orphan %s was not swept after the stuck alias errored — sweep must continue", orphan)
	}
	if got := fake.liveAliases(); got != 1 {
		t.Fatalf("liveAliases = %d, want 1 (only the stuck alias remains)", got)
	}
}

// TestSetupSurfacesPoolExhausted proves ErrPoolExhausted stays distinguishable
// (errors.Is) through the Setup seam once the /24 is full — the k3sm caller
// maps it to a pod event.
func TestSetupSurfacesPoolExhausted(t *testing.T) {
	n, _ := newTestNetwork(t)
	ctx := context.Background()

	for i := 0; i < n.alloc.Capacity(); i++ {
		if _, err := n.Setup(ctx, fmt.Sprintf("pod-%d", i)); err != nil {
			t.Fatalf("Setup pod-%d: %v", i, err)
		}
	}
	if _, err := n.Setup(ctx, "pod-overflow"); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("Setup on a full pool err = %v, want ErrPoolExhausted (distinguishable via errors.Is)", err)
	}
}

// stuckRemoveAliasManager wraps the fake but fails Remove for one address, to
// exercise the sweep's skip-and-collect error path.
type stuckRemoveAliasManager struct {
	*fakeAliasManager
	stuck netip.Addr
}

func (m *stuckRemoveAliasManager) Remove(ctx context.Context, ip netip.Addr) error {
	if ip == m.stuck {
		return errors.New("ifconfig -alias failed (test)")
	}
	return m.fakeAliasManager.Remove(ctx, ip)
}
