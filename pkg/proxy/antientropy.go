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
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	// antiEntropyConfirmDelay is how long a pass waits before re-listing to
	// confirm a divergence. A store that is only a watch delivery behind the LIST
	// catches up well inside it, so it is not repaired from a list that may by then
	// be the older of the two.
	antiEntropyConfirmDelay = time.Second
	// antiEntropyListTimeout bounds one uncached LIST round (all pages).
	antiEntropyListTimeout = 20 * time.Second
	// antiEntropyPageSize is the LIST page size.
	antiEntropyPageSize = 500
	// relistBackoffInitial and relistBackoffMax bound how soon after one relist
	// the next may run; the backoff doubles per relist and resets once a clean
	// pass follows an elapsed backoff.
	relistBackoffInitial = time.Minute
	relistBackoffMax     = 15 * time.Minute
	// relistSyncTimeout bounds the wait for a replacement informer set to sync.
	relistSyncTimeout = time.Minute
)

// liveLister reads Services and EndpointSlices straight from the API server,
// bypassing every cache. The anti-entropy pass compares it against the informer
// store; tests replace it.
type liveLister interface {
	listServices(ctx context.Context) ([]corev1.Service, error)
	listEndpointSlices(ctx context.Context) ([]discoveryv1.EndpointSlice, error)
}

// clientLister is the production liveLister: paginated LISTs with
// ResourceVersion "", which the API server serves as a quorum read rather than
// from its watch cache.
type clientLister struct {
	client kubernetes.Interface
}

func (l clientLister) listServices(ctx context.Context) ([]corev1.Service, error) {
	return listAll(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]corev1.Service, string, error) {
		list, err := l.client.CoreV1().Services(metav1.NamespaceAll).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
}

func (l clientLister) listEndpointSlices(ctx context.Context) ([]discoveryv1.EndpointSlice, error) {
	return listAll(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]discoveryv1.EndpointSlice, string, error) {
		list, err := l.client.DiscoveryV1().EndpointSlices(metav1.NamespaceAll).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
}

// listAll pages through one LIST. The first page carries ResourceVersion "" (a
// quorum read); continuation pages are served from that same snapshot.
func listAll[T any](ctx context.Context, page func(context.Context, metav1.ListOptions) ([]T, string, error)) ([]T, error) {
	var out []T
	opts := metav1.ListOptions{ResourceVersion: "", Limit: antiEntropyPageSize}
	for {
		items, cont, err := page(ctx, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		if cont == "" {
			return out, nil
		}
		opts.Continue = cont
	}
}

// serviceView is one source's Services and their EndpointSlices, keyed by the
// Service's "namespace/name".
type serviceView struct {
	svcs   map[string]*corev1.Service
	slices map[string][]*discoveryv1.EndpointSlice
}

func newServiceView() serviceView {
	return serviceView{
		svcs:   make(map[string]*corev1.Service),
		slices: make(map[string][]*discoveryv1.EndpointSlice),
	}
}

func (v serviceView) addService(svc *corev1.Service) {
	v.svcs[svc.Namespace+"/"+svc.Name] = svc
}

func (v serviceView) addSlice(sl *discoveryv1.EndpointSlice) {
	name := sl.Labels[discoveryv1.LabelServiceName]
	if name == "" {
		return
	}
	key := sl.Namespace + "/" + name
	v.slices[key] = append(v.slices[key], sl)
}

// listLive reads the live view through the lister.
func (w *Watcher) listLive(ctx context.Context) (serviceView, error) {
	ctx, cancel := context.WithTimeout(ctx, antiEntropyListTimeout)
	defer cancel()
	svcs, err := w.lister.listServices(ctx)
	if err != nil {
		return serviceView{}, err
	}
	slices, err := w.lister.listEndpointSlices(ctx)
	if err != nil {
		return serviceView{}, err
	}
	v := newServiceView()
	for i := range svcs {
		v.addService(&svcs[i])
	}
	for i := range slices {
		v.addSlice(&slices[i])
	}
	return v, nil
}

// storeView reads the informer store of set.
func storeView(set *informerSet) serviceView {
	v := newServiceView()
	for _, item := range set.svcs.GetStore().List() {
		if svc, ok := item.(*corev1.Service); ok {
			v.addService(svc)
		}
	}
	for _, item := range set.slices.GetStore().List() {
		if sl, ok := item.(*discoveryv1.EndpointSlice); ok {
			v.addSlice(sl)
		}
	}
	return v
}

// backendSets returns the Ready backend set the proxy would install for each of
// key's served ports under view: APIBackendSets over that one Service.
func (w *Watcher) backendSets(key string, v serviceView) map[PortKey]BackendSet {
	svc := v.svcs[key]
	if svc == nil {
		return nil
	}
	return APIBackendSets([]*corev1.Service{svc}, v.slices[key], w.static)
}

// divergences compares live against store per Service and returns the diverging
// Services' differences, keyed by "namespace/name".
func (w *Watcher) divergences(live, store serviceView) map[string][]Divergence {
	keys := make(map[string]struct{}, len(live.svcs)+len(store.svcs))
	for k := range live.svcs {
		keys[k] = struct{}{}
	}
	for k := range store.svcs {
		keys[k] = struct{}{}
	}
	out := make(map[string][]Divergence)
	for k := range keys {
		if d := DiffBackendSets(w.backendSets(k, live), w.backendSets(k, store)); len(d) > 0 {
			out[k] = d
		}
	}
	return out
}

// runAntiEntropy runs antiEntropyPass every interval until ctx is done.
func (w *Watcher) runAntiEntropy(ctx context.Context) {
	t := time.NewTicker(w.antiEntropy)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.antiEntropyPass(ctx)
		}
	}
}

// antiEntropyPass compares an uncached LIST against the informer store. On a
// divergence that survives a confirming re-list it warns per diverging Service
// port, repairs each diverging Service from the live objects, and replaces the
// informers (at most once per divergence episode, with a backoff) so the store
// itself converges. It reports whether a divergence was repaired.
func (w *Watcher) antiEntropyPass(ctx context.Context) bool {
	live, err := w.listLive(ctx)
	if err != nil {
		w.log.Warn("anti-entropy list failed; the informer store is unchecked this interval", "err", err)
		return false
	}
	divs := w.divergences(live, storeView(w.informers()))
	if len(divs) > 0 && w.confirmDelay > 0 {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(w.confirmDelay):
		}
		if live, err = w.listLive(ctx); err != nil {
			w.log.Warn("anti-entropy confirming list failed", "err", err)
			return false
		}
		divs = w.divergences(live, storeView(w.informers()))
	}
	if len(divs) == 0 {
		w.endEpisode()
		return false
	}
	for key, ds := range divs {
		for _, d := range ds {
			w.log.Warn("service backend set in the informer store diverges from the API server; repairing from a live list",
				"service", key, "vip", d.Key.String(),
				"storeBackends", len(d.Have), "liveBackends", len(d.Want),
				"missing", d.Missing, "extra", d.Extra)
		}
		w.repairService(key, live, ds)
	}
	w.maybeRelist(ctx)
	return true
}

// repairService reconciles the Service key from the live view: its live ports
// get their live backend sets, and any diverging port the live Service no longer
// serves is deleted. It holds the Service's reconcile stripe, like every other
// delivery.
func (w *Watcher) repairService(key string, live serviceView, ds []Divergence) {
	mu := w.serviceStripe(key)
	mu.Lock()
	defer mu.Unlock()
	liveSets := w.backendSets(key, live)
	if svc := live.svcs[key]; svc != nil {
		w.applyService(svc, live.slices[key])
	}
	for _, d := range ds {
		if _, ok := liveSets[d.Key]; !ok {
			w.proxy.ReconcileDelete(d.Key)
		}
	}
}

// maybeRelist replaces the informers unless this divergence episode already did
// or the backoff since the previous relist has not elapsed.
func (w *Watcher) maybeRelist(ctx context.Context) {
	if w.episodeRelisted || time.Now().Before(w.nextRelist) {
		return
	}
	w.episodeRelisted = true
	if w.relist(ctx) {
		w.nextRelist = time.Now().Add(w.relistBackoff)
		w.relistBackoff = min(2*w.relistBackoff, relistBackoffMax)
	}
}

// endEpisode records a clean pass: the next divergence starts a new episode, and
// the backoff resets once it has elapsed without a divergence in between.
func (w *Watcher) endEpisode() {
	w.episodeRelisted = false
	if !w.nextRelist.IsZero() && !time.Now().Before(w.nextRelist) {
		w.relistBackoff = relistBackoffInitial
	}
}

// relist replaces the informer set with a freshly listed one and reconciles every
// Service from it. The new set's handlers stay silent until it has synced and is
// swapped in; the old set keeps serving events until then, and is stopped right
// after. A Service the old store held but the new one does not (a lost delete)
// has its ports deleted. It reports whether the swap happened.
func (w *Watcher) relist(ctx context.Context) bool {
	old := w.informers()
	next := newInformerSet(w.client)
	if err := w.addHandlers(next); err != nil {
		w.log.Warn("anti-entropy relist: register handlers", "err", err)
		return false
	}
	next.factory.Start(next.stop)
	syncCtx, cancel := context.WithTimeout(ctx, relistSyncTimeout)
	defer cancel()
	if !cache.WaitForCacheSync(syncCtx.Done(), next.svcs.HasSynced, next.slices.HasSynced) {
		next.close()
		w.log.Warn("anti-entropy relist: replacement informers did not sync; keeping the current ones")
		return false
	}
	w.inf.Store(next)
	old.close()
	w.relists.Add(1)

	fresh := storeView(next)
	for key, svc := range storeView(old).svcs {
		if _, ok := fresh.svcs[key]; !ok {
			w.deleteServicePorts(svc)
		}
	}
	for _, svc := range fresh.svcs {
		w.reconcileService(svc)
	}
	w.log.Info("replaced the service informers after a store divergence", "services", len(fresh.svcs))
	return true
}
