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

package proxy

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	netv1 "k3sm.io/apis/net/v1"
)

// waitSynced polls w.Synced until it equals want or the deadline passes.
func waitSynced(t *testing.T, w *Watcher, want bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for w.Synced() != want {
		if time.Now().After(deadline) {
			t.Fatalf("Synced() never became %v", want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestWatcherSynced pins the sync signal through its lifecycle: false before
// Run, true once the informers synced and the table holds the store's backends,
// false across a relist until the fresh set is synced and applied, true again
// after, and false once Run returns.
func TestWatcherSynced(t *testing.T) {
	t.Parallel()
	key := PortKey{ClusterIP: orderVIP, Port: orderPort, Protocol: netv1.ProtocolTCP}
	client := fake.NewSimpleClientset(orderService(orderVIP, orderPort), orderSlice("10.42.0.5", 8080))

	// Hold the relist's Service LIST (the second one) until released, so the test
	// can observe the window between the relist starting and the fresh set syncing.
	var lists atomic.Int64
	held := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unhold := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unhold)
	client.PrependReactor("list", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
		if lists.Add(1) == 2 {
			close(held)
			<-release
		}
		return false, nil, nil
	})

	px, tbl := newOrderProxy(t)
	w := NewWatcher(client, px, slog.New(slog.DiscardHandler), WithAntiEntropyInterval(0))

	t.Run("false before Run", func(t *testing.T) {
		if w.Synced() || px.Synced() {
			t.Fatalf("before Run: Watcher.Synced() = %v, Proxy.Synced() = %v, want false", w.Synced(), px.Synced())
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = w.Run(ctx) }()

	t.Run("true after the informers sync, with the table installed", func(t *testing.T) {
		waitSynced(t, w, true)
		if !px.Synced() {
			t.Fatal("Proxy.Synced() does not mirror the Watcher")
		}
		// Applied before the signal flipped, not merely queued.
		if n := tbl.Len(key); n != 1 {
			t.Fatalf("Synced() is true but the table holds %d backends, want 1", n)
		}
	})

	relistDone := make(chan bool, 1)
	t.Run("false across a relist until the fresh set is applied", func(t *testing.T) {
		// Anti-entropy is disabled, so this test is the only relist driver.
		go func() { relistDone <- w.relist(ctx) }()
		select {
		case <-held:
		case <-time.After(10 * time.Second):
			t.Fatal("the relist never listed Services")
		}
		if w.Synced() || px.Synced() {
			t.Errorf("during the relist: Watcher.Synced() = %v, Proxy.Synced() = %v, want false", w.Synced(), px.Synced())
		}
		unhold()
		if ok := <-relistDone; !ok {
			t.Fatal("relist did not swap")
		}
		if !w.Synced() || !px.Synced() {
			t.Errorf("after the relist: Watcher.Synced() = %v, Proxy.Synced() = %v, want true", w.Synced(), px.Synced())
		}
		if n := tbl.Len(key); n != 1 {
			t.Errorf("table holds %d backends after the relist, want 1", n)
		}
	})

	t.Run("false after Run returns", func(t *testing.T) {
		cancel()
		<-runDone
		if w.Synced() || px.Synced() {
			t.Errorf("after Run: Watcher.Synced() = %v, Proxy.Synced() = %v, want false", w.Synced(), px.Synced())
		}
	})
}
