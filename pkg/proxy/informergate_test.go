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
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// establishedWatches observes when a fake.Clientset has actually opened its WATCH
// for a set of resources. wait blocks until every one of them is registered in the
// object tracker, so a Create issued afterwards is guaranteed to be delivered as a
// watch event.
//
// This is a readiness-boundary fix, not a timing workaround. A client-go reflector
// Lists, flips HasSynced, and only THEN opens its Watch; fake.Clientset's
// ObjectTracker.Watch ignores the ListOptions ResourceVersion entirely (client-go
// testing/fixture.go), so there is no replay. An object created inside that gap is
// carried by neither the List (it did not exist yet) nor the Watch (it was not
// registered yet) — and both watchers here run a 0 resync period, so nothing ever
// recovers the lost event and the table never converges. Under parallel load the
// gap widens from microseconds to seconds, which is exactly when the convergence
// assertions were observed to fail (B207). cache.WaitForCacheSync is therefore NOT
// a readiness signal for "a Create will be seen"; this is.
type establishedWatches struct {
	ready     <-chan struct{}
	resources []string
}

// watchGate installs the observation and returns its handle. It MUST be called
// before the watcher's Run, because it works by prepending a watch reactor that
// performs the tracker registration itself (mirroring fake.NewSimpleClientset's
// default reactor) and only then reports the resource ready — so the ready signal
// lands strictly after the watcher is in the tracker, never before.
func watchGate(client *fake.Clientset, resources ...string) *establishedWatches {
	var mu sync.Mutex
	pending := make(map[string]bool, len(resources))
	for _, r := range resources {
		pending[r] = true
	}
	ready := make(chan struct{})

	for _, r := range resources {
		res := r
		client.PrependWatchReactor(res, func(action k8stesting.Action) (bool, watch.Interface, error) {
			var opts metav1.ListOptions
			if wa, ok := action.(k8stesting.WatchActionImpl); ok {
				opts = wa.ListOptions
			}
			w, err := client.Tracker().Watch(action.GetResource(), action.GetNamespace(), opts)
			if err != nil {
				return false, nil, err
			}
			mu.Lock()
			if pending[res] {
				delete(pending, res)
				if len(pending) == 0 {
					close(ready)
				}
			}
			mu.Unlock()
			return true, w, nil
		})
	}
	return &establishedWatches{ready: ready, resources: resources}
}

// wait blocks until every watched resource is registered. The budget is a liveness
// backstop for a wedged informer, not a convergence window: once ready closes, the
// Create that follows is ordered by the tracker registration, not by any clock.
func (e *establishedWatches) wait(t *testing.T) {
	t.Helper()
	select {
	case <-e.ready:
	case <-time.After(30 * time.Second):
		t.Fatalf("fake watches for %v were never established", e.resources)
	}
}
