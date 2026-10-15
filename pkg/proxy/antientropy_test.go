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
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	netv1 "k3sm.io/apis/net/v1"
)

// withLiveLister replaces the anti-entropy pass's uncached reader.
func withLiveLister(l liveLister) WatcherOption {
	return func(w *Watcher) { w.lister = l }
}

// withConfirmDelay sets the pause before a divergence is confirmed.
func withConfirmDelay(d time.Duration) WatcherOption {
	return func(w *Watcher) { w.confirmDelay = d }
}

// countingLister wraps a liveLister and counts completed list rounds.
type countingLister struct {
	inner  liveLister
	rounds atomic.Int64
}

func (l *countingLister) listServices(ctx context.Context) ([]corev1.Service, string, error) {
	return l.inner.listServices(ctx)
}

func (l *countingLister) listEndpointSlices(ctx context.Context) ([]discoveryv1.EndpointSlice, string, error) {
	defer l.rounds.Add(1)
	return l.inner.listEndpointSlices(ctx)
}

// TestAntiEntropyRepairsALostSliceEvent loses one EndpointSlice watch event on
// purpose (the first EndpointSlice watch the informer opens never delivers
// anything) and proves the anti-entropy pass catches it: the uncached list
// returns a Ready backend the store lacks, the pass warns naming the Service, the
// VIP and both counts, repairs the routing table from the live objects, and
// relists exactly once, after which the fresh store holds the backend and the
// passes go quiet.
func TestAntiEntropyRepairsALostSliceEvent(t *testing.T) {
	t.Parallel()
	vip, port := orderVIP, int32(orderPort)
	key := PortKey{ClusterIP: vip, Port: port, Protocol: netv1.ProtocolTCP}

	client := fake.NewSimpleClientset(orderService(vip, port), orderSlice("10.42.0.5", 8080))
	var sliceWatches atomic.Int64
	deadWatchOpen := make(chan struct{})
	client.PrependWatchReactor("endpointslices", func(k8stesting.Action) (bool, watch.Interface, error) {
		if sliceWatches.Add(1) == 1 {
			close(deadWatchOpen)
			return true, watch.NewFake(), nil
		}
		return false, nil, nil
	})

	px, tbl := newOrderProxy(t)
	h := &captureHandler{}
	lister := &countingLister{inner: clientLister{client: client}}
	w := NewWatcher(client, px, slog.New(h),
		WithAntiEntropyInterval(20*time.Millisecond), withLiveLister(lister), withConfirmDelay(0))

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = w.Run(ctx) }()
	defer func() {
		cancel()
		<-runDone
	}()

	first := w.informers()
	if !cache.WaitForCacheSync(ctx.Done(), first.svcs.HasSynced, first.slices.HasSynced) {
		t.Fatal("informer cache sync failed")
	}
	waitBackends(t, tbl, key, 1)
	select {
	case <-deadWatchOpen:
	case <-time.After(10 * time.Second):
		t.Fatal("the EndpointSlice watch was never opened")
	}

	// The lost event: the slice exists in the API, but the dead watch never
	// delivers it to the first informer's store.
	second := orderSlice("10.42.0.6", 8080)
	second.Name = "web-def"
	if _, err := client.DiscoveryV1().EndpointSlices("default").Create(ctx, second, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create slice: %v", err)
	}

	waitBackends(t, tbl, key, 2)
	deadline := time.Now().Add(10 * time.Second)
	for w.relists.Load() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("the divergence never triggered a relist")
		}
		time.Sleep(5 * time.Millisecond)
	}

	divWarns := func() []slog.Record {
		var out []slog.Record
		for _, r := range h.warns() {
			if r.Message == "service backend set in the informer store diverges from the API server; repairing from a live list" {
				out = append(out, r)
			}
		}
		return out
	}
	warns := divWarns()
	if len(warns) == 0 {
		t.Fatal("no divergence Warn was emitted")
	}
	for attrKey, want := range map[string]string{
		"service":       "default/web",
		"vip":           key.String(),
		"storeBackends": "1",
		"liveBackends":  "2",
	} {
		if v, ok := attr(warns[0], attrKey); !ok || v != want {
			t.Errorf("divergence Warn %s = %q (present %v), want %q", attrKey, v, ok, want)
		}
	}

	// Converged: let several more passes run; none diverges, none relists, and the
	// table keeps both backends.
	settled := len(warns)
	start := lister.rounds.Load()
	for lister.rounds.Load() < start+5 {
		if time.Now().After(deadline) {
			t.Fatal("anti-entropy passes stopped running")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := len(divWarns()); n != settled {
		t.Errorf("after the relist the passes still diverge: %d Warns, want %d", n, settled)
	}
	if n := w.relists.Load(); n != 1 {
		t.Errorf("relists = %d, want exactly 1 for one divergence episode", n)
	}
	if n := tbl.Len(key); n != 2 {
		t.Errorf("routing table holds %d backends after the relist, want 2", n)
	}
	if w.informers() == first {
		t.Error("the informer set was not replaced")
	}
	if n := len(w.slicesForService("default", "web")); n != 2 {
		t.Errorf("the relisted store holds %d slices for default/web, want 2", n)
	}
}

// TestAntiEntropyDisabled pins the zero interval: no pass runs.
func TestAntiEntropyDisabled(t *testing.T) {
	t.Parallel()
	client := fake.NewSimpleClientset()
	lister := &countingLister{inner: clientLister{client: client}}
	w := NewWatcher(client, nil, slog.New(slog.DiscardHandler), WithAntiEntropyInterval(0), withLiveLister(lister))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = w.Run(ctx)
	if n := lister.rounds.Load(); n != 0 {
		t.Errorf("a disabled anti-entropy pass listed %d times, want 0", n)
	}
}
