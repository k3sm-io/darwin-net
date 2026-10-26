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
	"strconv"
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
	// divergenceSample caps how many missing and how many extra backends one
	// divergence Warn lists; the full counts ride beside them.
	divergenceSample = 8
	// relistBackoffInitial and relistBackoffMax bound how soon after one relist
	// the next may run; the backoff doubles per relist and resets once a clean
	// pass follows an elapsed backoff.
	relistBackoffInitial = time.Minute
	relistBackoffMax     = 15 * time.Minute
	// relistSyncTimeout bounds the wait for a replacement informer set to sync.
	relistSyncTimeout = time.Minute
)

// liveLister reads Services and EndpointSlices from the API server rather than
// from this process's informer store, and returns each list's resourceVersion (the snapshot
// the list was served at). The anti-entropy pass compares it against the
// informer store; tests replace it.
type liveLister interface {
	listServices(ctx context.Context) ([]corev1.Service, string, error)
	listEndpointSlices(ctx context.Context) ([]discoveryv1.EndpointSlice, string, error)
}

// clientLister is the production liveLister: paginated LISTs with
// ResourceVersion "", a consistent read at the latest resourceVersion (the API
// server may serve it from its watch cache once that has caught up, under
// ConsistentListFromCache).
type clientLister struct {
	client kubernetes.Interface
}

func (l clientLister) listServices(ctx context.Context) ([]corev1.Service, string, error) {
	return listAll(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]corev1.Service, metav1.ListMeta, error) {
		list, err := l.client.CoreV1().Services(metav1.NamespaceAll).List(ctx, opts)
		if err != nil {
			return nil, metav1.ListMeta{}, err
		}
		return list.Items, list.ListMeta, nil
	})
}

func (l clientLister) listEndpointSlices(ctx context.Context) ([]discoveryv1.EndpointSlice, string, error) {
	return listAll(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]discoveryv1.EndpointSlice, metav1.ListMeta, error) {
		list, err := l.client.DiscoveryV1().EndpointSlices(metav1.NamespaceAll).List(ctx, opts)
		if err != nil {
			return nil, metav1.ListMeta{}, err
		}
		return list.Items, list.ListMeta, nil
	})
}

// listAll pages through one LIST and returns the items and the first page's
// resourceVersion. The first page carries ResourceVersion "" (a consistent read);
// continuation pages are served from that same snapshot.
func listAll[T any](ctx context.Context, page func(context.Context, metav1.ListOptions) ([]T, metav1.ListMeta, error)) ([]T, string, error) {
	var (
		out []T
		rv  string
	)
	opts := metav1.ListOptions{ResourceVersion: "", Limit: antiEntropyPageSize}
	for {
		items, meta, err := page(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		if opts.Continue == "" {
			rv = meta.ResourceVersion
		}
		out = append(out, items...)
		if meta.Continue == "" {
			return out, rv, nil
		}
		opts.Continue = meta.Continue
	}
}

// serviceView is one source's Services and their EndpointSlices, keyed by the
// Service's "namespace/name". svcRV and sliceRV are the live lists'
// resourceVersions; a store view leaves them empty.
type serviceView struct {
	svcs    map[string]*corev1.Service
	slices  map[string][]*discoveryv1.EndpointSlice
	svcRV   string
	sliceRV string
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
	svcs, svcRV, err := w.lister.listServices(ctx)
	if err != nil {
		return serviceView{}, err
	}
	slices, sliceRV, err := w.lister.listEndpointSlices(ctx)
	if err != nil {
		return serviceView{}, err
	}
	v := newServiceView()
	v.svcRV, v.sliceRV = svcRV, sliceRV
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
// divergence that survives a confirming re-list it reports each diverging port
// (a Warn once per key per episode, Debug while it persists), repairs each
// diverging Service from the live objects unless the circuit breaker holds, and
// replaces the informers (at most once per divergence episode, with a backoff)
// so the store itself converges. It reports whether a divergence was found.
func (w *Watcher) antiEntropyPass(ctx context.Context) bool {
	live, err := w.listLive(ctx)
	if err != nil {
		w.log.Warn("anti-entropy list failed; the informer store is unchecked this interval", "err", err)
		return false
	}
	store := storeView(w.informers())
	divs := w.divergences(live, store)
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
		store = storeView(w.informers())
		divs = w.divergences(live, store)
	}
	w.settleRepaired(store, divs)
	w.endKeyEpisodes(divs)
	if len(divs) == 0 {
		w.endEpisode()
		return false
	}
	w.reportDivergences(divs)
	if w.breakerTripped(live, store, divs) {
		if !w.breakerWarned {
			w.breakerWarned = true
			w.log.Warn("anti-entropy repair withheld: the live list would remove backends from most Services at once; leaving the routing table as it is and relisting",
				"liveServices", len(live.svcs), "storeServices", len(store.svcs), "divergingServices", len(divs))
		} else {
			w.log.Debug("anti-entropy repair still withheld", "liveServices", len(live.svcs), "storeServices", len(store.svcs))
		}
		w.maybeRelist(ctx)
		return true
	}
	for key, ds := range divs {
		w.repairService(key, live, ds)
	}
	w.maybeRelist(ctx)
	return true
}

// reportDivergences logs each diverging port: a Warn the first time a key
// diverges in its episode, Debug on later passes while it persists. Each line
// lists at most divergenceSample missing and extra backends beside the counts.
func (w *Watcher) reportDivergences(divs map[string][]Divergence) {
	for key, ds := range divs {
		for _, d := range ds {
			args := []any{
				"service", key, "vip", d.Key.String(),
				"storeBackends", len(d.Have), "liveBackends", len(d.Want),
				"missing", sample(d.Missing), "missingCount", len(d.Missing),
				"extra", sample(d.Extra), "extraCount", len(d.Extra),
			}
			if w.divWarned[d.Key] {
				w.log.Debug("service backend set divergence persists", args...)
				continue
			}
			w.divWarned[d.Key] = true
			w.log.Warn("service backend set in the informer store diverges from the API server; repairing from a live list", args...)
		}
	}
}

// sample returns at most divergenceSample leading elements of s.
func sample(s []string) []string {
	return s[:min(len(s), divergenceSample)]
}

// endKeyEpisodes ends the per-key Warn episode of every key not diverging now.
func (w *Watcher) endKeyEpisodes(divs map[string][]Divergence) {
	now := make(map[PortKey]bool)
	for _, ds := range divs {
		for _, d := range ds {
			now[d.Key] = true
		}
	}
	for k := range w.divWarned {
		if !now[k] {
			delete(w.divWarned, k)
		}
	}
}

// breakerTripped reports whether repairing divs from live would be destructive
// enough to look like a broken source rather than lost events: the live list
// holds no Service while the store holds some, or more than half of the store's
// Services that have a Ready backend would lose at least one. An API server
// restarted on an empty or restored datastore must not empty the node's routing
// table in one pass; the relist the pass still requests is what then converges.
func (w *Watcher) breakerTripped(live, store serviceView, divs map[string][]Divergence) bool {
	if len(live.svcs) == 0 && len(store.svcs) > 0 {
		return true
	}
	withReady, losing := 0, 0
	for key := range store.svcs {
		if !anyBackend(w.backendSets(key, store)) {
			continue
		}
		withReady++
		for _, d := range divs[key] {
			if len(d.Extra) > 0 {
				losing++
				break
			}
		}
	}
	return withReady > 0 && 2*losing > withReady
}

// anyBackend reports whether any set in sets is non-empty.
func anyBackend(sets map[PortKey]BackendSet) bool {
	for _, s := range sets {
		if len(s) > 0 {
			return true
		}
	}
	return false
}

// repairService reconciles the Service key from the live view: its live ports
// get their live backend sets, and any diverging port the live Service no longer
// serves is deleted. It holds the Service's reconcile stripe, like every other
// delivery, and first re-checks the store under it: when the store already holds
// a newer object for the Service than the live lists were served at (a watch
// event landed in the confirm gap), the store wins and the repair is skipped.
func (w *Watcher) repairService(key string, live serviceView, ds []Divergence) {
	mu := w.serviceStripe(key)
	mu.Lock()
	defer mu.Unlock()
	if obj, rv := w.storeNewerThan(key, live); obj != "" {
		w.log.Debug("anti-entropy repair skipped: the store already holds a newer object",
			"service", key, "object", obj, "resourceVersion", rv)
		return
	}
	liveSets := w.backendSets(key, live)
	if svc := live.svcs[key]; svc != nil {
		w.applyService(svc, live.slices[key])
	}
	for _, d := range ds {
		if _, ok := liveSets[d.Key]; !ok {
			w.proxy.ReconcileDelete(d.Key)
		}
	}
	w.repairedFromLive[key] = true
}

// storeNewerThan returns the kind/name and resourceVersion of the first object
// the current store holds for Service key that is newer than the live list it
// would be repaired from, or "" when there is none. resourceVersions are compared
// as integers (etcd and kine both issue them so); a value that does not parse is
// not treated as newer, and the relist that follows the repair is the backstop.
func (w *Watcher) storeNewerThan(key string, live serviceView) (string, string) {
	set := w.informers()
	if item, ok, err := set.svcs.GetStore().GetByKey(key); err == nil && ok {
		if svc, ok := item.(*corev1.Service); ok && rvNewer(svc.ResourceVersion, live.svcRV) {
			return "Service/" + svc.Name, svc.ResourceVersion
		}
	}
	ns, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return "", ""
	}
	for _, sl := range w.slicesForService(ns, name) {
		if rvNewer(sl.ResourceVersion, live.sliceRV) {
			return "EndpointSlice/" + sl.Name, sl.ResourceVersion
		}
	}
	return "", ""
}

// rvNewer reports whether resourceVersion a is strictly newer than b, when both
// are integers.
func rvNewer(a, b string) bool {
	x, errA := strconv.ParseUint(a, 10, 64)
	y, errB := strconv.ParseUint(b, 10, 64)
	return errA == nil && errB == nil && x > y
}

// settleRepaired re-delivers, from the store, every Service last repaired from a
// live list that no longer diverges, so the table follows the store again (a
// delete the store observed after the list leaves no repaired backend behind).
func (w *Watcher) settleRepaired(store serviceView, divs map[string][]Divergence) {
	for key := range w.repairedFromLive {
		if _, still := divs[key]; still {
			continue
		}
		delete(w.repairedFromLive, key)
		if svc := store.svcs[key]; svc != nil {
			w.reconcileService(svc)
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
	w.breakerWarned = false
	if !w.nextRelist.IsZero() && !time.Now().Before(w.nextRelist) {
		w.relistBackoff = relistBackoffInitial
	}
}

// relist replaces the informer set with a freshly listed one and reconciles every
// Service from it. The new set's handlers stay silent until it has synced and is
// swapped in; the old set keeps serving events until then, and is stopped right
// after. The swap holds swapMu exclusively, so no handler of the old set is
// delivering across it. A Service the old store held but the new one does not (a
// lost delete) has its ports deleted. It reports whether the swap happened.
func (w *Watcher) relist(ctx context.Context) bool {
	old := w.informers()
	next := newInformerSet(w.client)
	if err := w.addHandlers(next); err != nil {
		w.log.Warn("anti-entropy relist: register handlers", "err", err)
		return false
	}
	// Not synced until the fresh set is applied. A failed sync keeps the old set,
	// which is still synced and applied, so it restores the signal.
	wasSynced := w.synced.Load()
	w.setSynced(false)
	next.factory.Start(next.stop)
	syncCtx, cancel := context.WithTimeout(ctx, relistSyncTimeout)
	defer cancel()
	if !cache.WaitForCacheSync(syncCtx.Done(), next.svcs.HasSynced, next.slices.HasSynced) {
		next.close()
		w.setSynced(wasSynced)
		w.log.Warn("anti-entropy relist: replacement informers did not sync; keeping the current ones")
		return false
	}
	w.swapMu.Lock()
	w.inf.Store(next)
	w.swapMu.Unlock()
	old.close()
	w.relists.Add(1)

	fresh := storeView(next)
	for key, svc := range storeView(old).svcs {
		if _, ok := fresh.svcs[key]; !ok {
			w.deleteServicePorts(svc)
		}
	}
	if w.applyStore(ctx, next) {
		w.setSynced(true)
	}
	clear(w.repairedFromLive)
	w.log.Info("replaced the service informers after a store divergence", "services", len(fresh.svcs))
	return true
}
