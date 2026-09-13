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

package mesh

import (
	"context"
	"net/netip"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	netv1 "k3sm.io/apis/net/v1"
)

// newTestWatcher builds a Watcher over an injected fakeDevice. A dummy REST config
// is enough: NewWatcher builds the REST client + informer without any I/O (the
// informer is never Run in these tests), so the wiring can be asserted and the
// resync/handler paths driven against the informer's cache directly.
func newTestWatcher(t *testing.T) (*Watcher, *fakeDevice) {
	t.Helper()
	fake := &fakeDevice{}
	m, err := New(netip.MustParsePrefix("100.64.0.0/24"), withDevice(fake), WithLogger(discardLogger()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	w, err := NewWatcher(&rest.Config{Host: "https://127.0.0.1:1"}, m, discardLogger())
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	return w, fake
}

// seedPeer adds a MeshPeer at the given resourceVersion to the watcher's informer
// cache and returns it, so a test can hand it to the event handler as an update's
// old/new object.
func seedPeer(t *testing.T, w *Watcher, name, podCIDR, endpoint string, seed byte, resourceVersion string) *netv1.MeshPeer {
	t.Helper()
	peer := &netv1.MeshPeer{
		ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: resourceVersion},
		Spec:       peerSpec(name, podCIDR, endpoint, seed),
	}
	if err := w.informer.GetStore().Add(peer); err != nil {
		t.Fatalf("seed informer store: %v", err)
	}
	return peer
}

// waitForApplies blocks until the fake device has recorded at least want Apply
// calls, or fails the test. It bounds a wait for work the watcher does on its own
// goroutine; it never waits a real resync period.
func waitForApplies(t *testing.T, fake *fakeDevice, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fake.applyCount() >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("Apply called %d times, want at least %d", fake.applyCount(), want)
}

// TestMeshWatcherResyncReconverges is the M3 reconvergence guard: the watcher drives
// a bounded periodic resync, and a resync that fires with NO MeshPeer change still
// re-drives Device.Apply on the unchanged snapshot. That periodic re-assertion is
// what brings the utun/wireguard back after the root netd helper restarts (the device
// lives in the netd process and is lost on restart); without it nothing would
// re-issue ConfigureMesh until an unrelated MeshPeer change, so the cross-node mesh
// would stay down indefinitely.
//
// Fails-before: with no periodic driver (resync period 0 and no ticker) the period
// assertion fails and nothing re-drives Apply on a timer. Passes-after: the ticker
// runs at meshResyncPeriod.
func TestMeshWatcherResyncReconverges(t *testing.T) {
	// The bounded period the watcher's ticker runs at must be non-zero — it is the
	// reconvergence floor after a netd restart.
	if meshResyncPeriod <= 0 {
		t.Fatalf("meshResyncPeriod = %v, want a bounded non-zero resync", meshResyncPeriod)
	}

	w, fake := newTestWatcher(t)
	if w.resyncPeriod != meshResyncPeriod {
		t.Fatalf("watcher resyncPeriod = %v, want %v (the ticker must run at the bounded resync period)", w.resyncPeriod, meshResyncPeriod)
	}

	// Seed the informer cache with a steady peer set and make NO further change —
	// exactly the post-restart steady state (the desired state is unchanged; only
	// the in-process device was lost).
	seedPeer(t, w, "nodeB", "100.64.1.0/24", "192.0.2.10:51820", 0x42, "1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The initial reconcile programs the mesh from the snapshot.
	w.resync(ctx)
	if got := fake.applyCount(); got != 1 {
		t.Fatalf("after initial reconcile, Apply called %d times, want 1", got)
	}

	// A periodic resync fires with NO MeshPeer change. This is what the watcher's
	// ticker drives every meshResyncPeriod; it must re-apply the same desired state
	// so the utun/wireguard reconverges after a netd restart. The tick channel is
	// driven by the test so no real period elapses.
	ticks := make(chan time.Time)
	done := make(chan error, 1)
	go func() { done <- w.resyncLoop(ctx, ticks) }()
	ticks <- time.Now()
	waitForApplies(t, fake, 2)
	cancel()
	<-done

	if got := fake.applyCount(); got != 2 {
		t.Fatalf("resync without a MeshPeer change re-drove Apply %d times, want 2 (the mesh would not reconverge after a netd restart)", got)
	}
	last := fake.last()
	if len(last.Routes) != 1 || last.Routes[0].String() != "100.64.1.0/24" {
		t.Fatalf("resync re-applied routes = %v, want [100.64.1.0/24] (same desired state re-asserted)", last.Routes)
	}
}

// TestMeshWatcherCoalescesResync pins the reconcile FAN-OUT, which is the cost side
// of the reconvergence guard above: one periodic tick is exactly ONE full-snapshot
// Reconcile no matter how many MeshPeers are cached, and an informer update that
// carries no actual change is none at all.
//
// Fails-before: with the informer built at meshResyncPeriod and an unconditional
// UpdateFunc, every resync re-delivered the whole cache object by object, so an
// N-node cluster ran N Reconciles — N ConfigureMesh RPCs to the root netd helper —
// per tick (observed as two "mesh reconciled" lines 2ms apart on two nodes). The
// per-peer routes and the endpoint-roaming contract in plan.go are unchanged; only
// the number of times the identical snapshot is applied is.
func TestMeshWatcherCoalescesResync(t *testing.T) {
	t.Run("one tick reconciles once with two peers cached", func(t *testing.T) {
		w, fake := newTestWatcher(t)
		seedPeer(t, w, "nodeB", "100.64.1.0/24", "192.0.2.10:51820", 0x42, "1")
		seedPeer(t, w, "nodeC", "100.64.2.0/24", "192.0.2.11:51820", 0x43, "1")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ticks := make(chan time.Time)
		done := make(chan error, 1)
		go func() { done <- w.resyncLoop(ctx, ticks) }()
		ticks <- time.Now()
		waitForApplies(t, fake, 1)
		cancel()
		<-done

		// The loop has exited, so the count is final: one tick, one Reconcile —
		// not one per cached peer.
		if got := fake.applyCount(); got != 1 {
			t.Fatalf("one periodic tick drove Apply %d times with 2 peers cached, want 1", got)
		}
		last := fake.last()
		if len(last.Peers) != 2 {
			t.Fatalf("the single reconcile applied %d peers, want 2 (the tick must carry the FULL snapshot)", len(last.Peers))
		}
	})

	t.Run("update with an unchanged ResourceVersion does not reconcile", func(t *testing.T) {
		w, fake := newTestWatcher(t)
		peer := seedPeer(t, w, "nodeB", "100.64.1.0/24", "192.0.2.10:51820", 0x42, "7")

		h := w.handler(context.Background())
		h.UpdateFunc(peer, peer.DeepCopy())
		if got := fake.applyCount(); got != 0 {
			t.Fatalf("a re-delivery of an unchanged MeshPeer drove Apply %d times, want 0", got)
		}
	})

	t.Run("update with a changed ResourceVersion reconciles once", func(t *testing.T) {
		w, fake := newTestWatcher(t)
		peer := seedPeer(t, w, "nodeB", "100.64.1.0/24", "192.0.2.10:51820", 0x42, "7")
		updated := peer.DeepCopy()
		updated.ResourceVersion = "8"
		updated.Spec = peerSpec("nodeB", "100.64.1.0/24", "192.0.2.99:51820", 0x42)
		if err := w.informer.GetStore().Update(updated); err != nil {
			t.Fatalf("update informer store: %v", err)
		}

		h := w.handler(context.Background())
		h.UpdateFunc(peer, updated)
		if got := fake.applyCount(); got != 1 {
			t.Fatalf("a real MeshPeer change drove Apply %d times, want 1", got)
		}
		if len(fake.last().Peers) != 1 {
			t.Fatalf("the reconcile applied %d peers, want 1 (the FULL snapshot from the cache)", len(fake.last().Peers))
		}
	})

	t.Run("add and delete always reconcile", func(t *testing.T) {
		w, fake := newTestWatcher(t)
		peer := seedPeer(t, w, "nodeB", "100.64.1.0/24", "192.0.2.10:51820", 0x42, "1")

		h := w.handler(context.Background())
		h.AddFunc(peer)
		if got := fake.applyCount(); got != 1 {
			t.Fatalf("AddFunc drove Apply %d times, want 1", got)
		}
		if err := w.informer.GetStore().Delete(peer); err != nil {
			t.Fatalf("delete from informer store: %v", err)
		}
		h.DeleteFunc(peer)
		if got := fake.applyCount(); got != 2 {
			t.Fatalf("DeleteFunc drove Apply %d times, want 2", got)
		}
		if len(fake.last().Peers) != 0 {
			t.Fatalf("after the delete the snapshot carried %d peers, want 0", len(fake.last().Peers))
		}
	})
}
