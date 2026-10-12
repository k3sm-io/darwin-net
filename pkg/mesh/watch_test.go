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
	"fmt"
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

// waitUntil polls cond for up to two seconds and fails the test if it never holds.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// armed reports whether the watcher's one-slot trigger currently holds a pass,
// without consuming it. It is the deterministic way to assert that a handler did
// or did not arm a reconcile: there is no goroutine to wait on and no timeout to
// pick.
func armed(w *Watcher) bool { return len(w.kick) == 1 }

// startLoop runs the watcher's reconcile loop on its own goroutine, driven by the
// returned tick channel, and returns a stop func that cancels it and waits for it
// to exit — after stop the fake's counts are final.
func startLoop(t *testing.T, w *Watcher) (ticks chan time.Time, stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ticks = make(chan time.Time)
	done := make(chan error, 1)
	go func() { done <- w.reconcileLoop(ctx, ticks) }()
	return ticks, func() {
		cancel()
		if err := <-done; err != context.Canceled {
			t.Fatalf("reconcileLoop returned %v, want context.Canceled", err)
		}
	}
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
	go func() { done <- w.reconcileLoop(ctx, ticks) }()
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

		ticks, stop := startLoop(t, w)
		ticks <- time.Now()
		waitForApplies(t, fake, 1)
		stop()

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

		h := w.handler()
		h.UpdateFunc(peer, peer.DeepCopy())
		if armed(w) {
			t.Fatalf("a re-delivery of an unchanged MeshPeer armed a reconcile, want none")
		}
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

		h := w.handler()
		h.UpdateFunc(peer, updated)
		if !armed(w) {
			t.Fatalf("a real MeshPeer change did not arm a reconcile")
		}
		_, stop := startLoop(t, w)
		waitForApplies(t, fake, 1)
		stop()
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

		h := w.handler()
		_, stop := startLoop(t, w)
		h.AddFunc(peer)
		waitForApplies(t, fake, 1)
		if err := w.informer.GetStore().Delete(peer); err != nil {
			t.Fatalf("delete from informer store: %v", err)
		}
		h.DeleteFunc(peer)
		waitForApplies(t, fake, 2)
		stop()
		if got := fake.applyCount(); got != 2 {
			t.Fatalf("add then delete drove Apply %d times, want 2", got)
		}
		if len(fake.last().Peers) != 0 {
			t.Fatalf("after the delete the snapshot carried %d peers, want 0", len(fake.last().Peers))
		}
	})
}

// TestMeshWatcherCoalescesEvents pins the EVENT side of the fan-out: informer
// events do not reconcile inline, they arm a one-slot trigger that a single loop
// drains, so a burst of events is one pass, and an event that lands while a pass
// is running neither blocks the informer nor gets lost.
//
// Fails-before: with the handlers calling resync inline, N adds were N full
// passes — N ConfigureMesh RPCs to netd during the initial list of an N-node
// cluster — and an add delivered during a pass blocked the informer's delivery
// goroutine on Mesh.mu until the device write finished. The per-peer routes and
// the endpoint-roaming contract in plan.go are unchanged; only when and how many
// times the snapshot is applied is.
func TestMeshWatcherCoalescesEvents(t *testing.T) {
	t.Run("a burst of adds is one pass with the full snapshot", func(t *testing.T) {
		w, fake := newTestWatcher(t)
		h := w.handler()
		const n = 8
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("node%d", i)
			h.AddFunc(seedPeer(t, w, name, fmt.Sprintf("100.64.%d.0/24", i+1), fmt.Sprintf("192.0.2.%d:51820", 10+i), byte(0x42+i), "1"))
		}
		if !armed(w) {
			t.Fatalf("%d adds did not arm a reconcile", n)
		}
		if got := fake.applyCount(); got != 0 {
			t.Fatalf("the handlers drove Apply %d times themselves, want 0 (a handler must not reconcile inline)", got)
		}

		_, stop := startLoop(t, w)
		waitForApplies(t, fake, 1)
		stop()
		if got := fake.applyCount(); got != 1 {
			t.Fatalf("%d adds drove Apply %d times, want 1", n, got)
		}
		if got := len(fake.last().Peers); got != n {
			t.Fatalf("the single pass applied %d peers, want %d (the pass must carry the FULL snapshot)", got, n)
		}
	})

	t.Run("an event during a pass does not block the informer and is not lost", func(t *testing.T) {
		w, fake := newTestWatcher(t)
		fake.gate = make(chan struct{})
		h := w.handler()
		// The gate is armed before the loop is running to drain anything, so
		// if a handler ever reconciled inline this seed would block forever on
		// the fake's gate with nobody to release it. Guard it exactly like the
		// in-flight add below: run it off the test goroutine and bound the wait.
		seeded := make(chan struct{})
		go func() {
			h.AddFunc(seedPeer(t, w, "nodeB", "100.64.1.0/24", "192.0.2.10:51820", 0x42, "1"))
			close(seeded)
		}()
		select {
		case <-seeded:
		case <-time.After(2 * time.Second):
			t.Fatalf("AddFunc blocked before the loop started; a handler must never wait on the device")
		}
		_, stop := startLoop(t, w)

		// The loop drains the slot and starts the first pass, which parks inside
		// Device.Apply on the fake's gate (with Mesh.mu held, as in production).
		// Once the slot is empty the pass is committed, so a second add delivered
		// now — from the informer's point of view — lands in the slot and owes
		// exactly one further pass. The handler must return at once: it arms the
		// trigger and does not wait for the device.
		waitUntil(t, "the loop to drain the trigger", func() bool { return !armed(w) })
		returned := make(chan struct{})
		go func() {
			h.AddFunc(seedPeer(t, w, "nodeC", "100.64.2.0/24", "192.0.2.11:51820", 0x43, "1"))
			close(returned)
		}()
		select {
		case <-returned:
		case <-time.After(2 * time.Second):
			t.Fatalf("AddFunc blocked behind a running reconcile pass; a handler must never wait on the device")
		}

		if !armed(w) {
			t.Fatalf("an add during a running pass did not arm the next pass (the add would be lost)")
		}
		// The first pass is still parked, so nothing is recorded yet. Release it,
		// then the one pass the in-flight add owes.
		fake.gate <- struct{}{}
		fake.gate <- struct{}{}
		waitForApplies(t, fake, 2)
		stop()
		if got := fake.applyCount(); got != 2 {
			t.Fatalf("an add during a pass drove Apply %d times in total, want 2 (one pass owed, none lost)", got)
		}
		if got := len(fake.last().Peers); got != 2 {
			t.Fatalf("the pass after the in-flight add applied %d peers, want 2 (the add must not be lost)", got)
		}
	})
}
