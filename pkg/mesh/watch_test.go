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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	netv1 "k3sm.io/apis/net/v1"
)

// TestMeshWatcherResyncReconverges is the M3 reconvergence guard: the MeshPeer
// informer is created with a non-zero (bounded) resync period, and a resync that
// fires with NO MeshPeer change still re-drives Device.Apply on the unchanged
// snapshot. That periodic re-assertion is what brings the utun/wireguard back after
// the root netd helper restarts (the device lives in the netd process and is lost on
// restart); with resync=0 nothing would re-issue ConfigureMesh until an unrelated
// MeshPeer change, so the cross-node mesh would stay down indefinitely.
//
// Fails-before: if the informer is reverted to resync period 0 the period assertion
// fails (and nothing would re-drive Apply on a timer). Passes-after: meshResyncPeriod.
func TestMeshWatcherResyncReconverges(t *testing.T) {
	// The bounded resync period the watcher hands the informer must be non-zero —
	// it is the reconvergence floor after a netd restart.
	if meshResyncPeriod <= 0 {
		t.Fatalf("meshResyncPeriod = %v, want a bounded non-zero resync", meshResyncPeriod)
	}

	fake := &fakeDevice{}
	m, err := New(netip.MustParsePrefix("100.64.0.0/24"), withDevice(fake), WithLogger(discardLogger()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A dummy REST config is enough: NewWatcher builds the REST client + informer
	// without any I/O (the informer is never Run here), so we can assert the wiring
	// and drive the resync path against the informer's cache directly.
	w, err := NewWatcher(&rest.Config{Host: "https://127.0.0.1:1"}, m, discardLogger())
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	if w.resyncPeriod != meshResyncPeriod {
		t.Fatalf("watcher resyncPeriod = %v, want %v (the informer must be created with the bounded resync)", w.resyncPeriod, meshResyncPeriod)
	}

	// Seed the informer cache with a steady peer set and make NO further change —
	// exactly the post-restart steady state (the desired state is unchanged; only
	// the in-process device was lost).
	peer := &netv1.MeshPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "nodeB"},
		Spec:       peerSpec("nodeB", "100.64.1.0/24", "192.0.2.10:51820", 0x42),
	}
	if err := w.informer.GetStore().Add(peer); err != nil {
		t.Fatalf("seed informer store: %v", err)
	}

	ctx := context.Background()

	// The initial reconcile programs the mesh from the snapshot.
	w.resync(ctx)
	if got := fake.applyCount(); got != 1 {
		t.Fatalf("after initial reconcile, Apply called %d times, want 1", got)
	}

	// A periodic resync fires with NO MeshPeer change. This is what the informer's
	// bounded resyncPeriod drives every meshResyncPeriod; it must re-apply the same
	// desired state so the utun/wireguard reconverges after a netd restart.
	w.resync(ctx)
	if got := fake.applyCount(); got != 2 {
		t.Fatalf("resync without a MeshPeer change re-drove Apply %d times, want 2 (the mesh would not reconverge after a netd restart)", got)
	}
	last := fake.last()
	if len(last.Routes) != 1 || last.Routes[0].String() != "100.64.1.0/24" {
		t.Fatalf("resync re-applied routes = %v, want [100.64.1.0/24] (same desired state re-asserted)", last.Routes)
	}
}
