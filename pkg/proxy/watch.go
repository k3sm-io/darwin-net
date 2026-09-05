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
	"fmt"
	"log/slog"
	"sync"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	netv1 "k3sm.io/apis/net/v1"
)

// Watcher drives a Proxy from Kubernetes Service and EndpointSlice informers. It
// is the production watch seam: on every Service or EndpointSlice event it
// recomputes the affected Service's desired state and calls Proxy.Reconcile,
// which routes each port to its single per-VIP worker. The informers' shared
// cache makes the recompute cheap; event ordering is irrelevant because every
// recompute derives the FULL desired state from the caches rather than applying a
// delta.
//
// That last property only holds if a recompute's snapshot cannot be overtaken by
// an older one — see reconcileMu, which is what makes it true.
type Watcher struct {
	proxy   *Proxy
	factory informers.SharedInformerFactory
	svcs    cache.SharedIndexInformer
	slices  cache.SharedIndexInformer
	log     *slog.Logger

	// eTPLocalWarned throttles the externalTrafficPolicy:Local-unhonored datapath
	// Warn to once per contiguous eTP:Local-on-NodePort episode, keyed by
	// "namespace/name". It is touched ONLY from onService / onServiceDelete, which
	// are the SAME single Service-informer handler goroutine, so it is race-free by
	// that discipline; reconcileService (also driven by the EndpointSlice informer
	// goroutine) must NOT touch it. eTPMu guards it anyway as defense-in-depth: the
	// single-goroutine property is an implicit client-go behavior, and the failure
	// mode of a future refactor breaking it is a fatal `concurrent map writes` throw
	// that crashes k3sm-netd (a node data-path DoS), so the near-free lock removes
	// the reliance on an un-contracted invariant.
	eTPMu          sync.Mutex
	eTPLocalWarned map[string]bool

	// reconcileMu serializes each Service's SNAPSHOT-AND-DELIVER, striped by
	// Service key (see serviceStripe). Both informer goroutines call
	// reconcileService, and each one reads the EndpointSlice cache and THEN hands
	// the resulting backend set to the per-VIP worker. Those two steps are not
	// atomic, so without this lock a goroutine descheduled between them can deliver
	// a STALE snapshot after a fresher one:
	//
	//	Service handler:  snapshot slices -> [] ......................... send []
	//	Slice handler:            snapshot slices -> [pod] -> send [pod]
	//
	// The worker applies both in arrival order, so the table ends on the empty set
	// and — the informers run a 0 resync period — nothing ever recomputes it. The
	// Service blackholes until its next real event. The proxy's per-VIP worker
	// serializes DELIVERY, which is not the same guarantee.
	//
	// Striping bounds the contention: only Services that hash together wait on each
	// other. The lock is held across ReconcilePolicy, whose sole blocking point is a
	// buffered per-worker channel drained by a loop with no unbounded wait, so it is
	// never held on a network round-trip. It is NOT held while onService runs the
	// eTP Warn (eTPMu is taken and released before this one — the two never nest).
	reconcileMu [reconcileStripes]sync.Mutex

	// static maps "namespace/name" Service keys to a FIXED backend set that
	// replaces the EndpointSlice-derived one for that Service (every port routes
	// to these endpoints; each Endpoint carries its own dial port). It exists for
	// exactly one shape: a backend that CANNOT have an EndpointSlice — upstream
	// validation hard-rejects loopback endpoint addresses on create, so a
	// loopback-advertising single-node apiserver can publish no slice for the
	// kubernetes Service (neither can anyone else on its behalf). Set at
	// construction (WithStaticBackends), read-only afterwards — no lock needed.
	static map[string][]netv1.Endpoint
}

// WatcherOption customizes a Watcher at construction.
type WatcherOption func(*Watcher)

// WithStaticBackends pins the given Services to fixed backend sets, keyed
// "namespace/name". An entry fully replaces the Service's EndpointSlice-derived
// backends: reconciles route every port of that Service to the given endpoints
// (each Endpoint's own Port is the dial port) and ignore any slice that appears.
// Use ONLY for a backend no EndpointSlice can represent (the loopback-bound
// apiserver); everything else must flow from real slices.
func WithStaticBackends(backends map[string][]netv1.Endpoint) WatcherOption {
	return func(w *Watcher) { w.static = backends }
}

// NewWatcher builds a Watcher over client for the given Proxy. It wires Service
// and EndpointSlice informers but does not start them; call Run.
func NewWatcher(client kubernetes.Interface, proxy *Proxy, log *slog.Logger, opts ...WatcherOption) *Watcher {
	if log == nil {
		log = slog.Default()
	}
	f := informers.NewSharedInformerFactory(client, 0)
	w := &Watcher{
		proxy:          proxy,
		factory:        f,
		svcs:           f.Core().V1().Services().Informer(),
		slices:         f.Discovery().V1().EndpointSlices().Informer(),
		log:            log,
		eTPLocalWarned: make(map[string]bool),
	}
	for _, o := range opts {
		o(w)
	}
	return w
}

// Run starts the informers and blocks until ctx is cancelled. It registers event
// handlers that reconcile the affected Service on any Service or EndpointSlice
// change, then waits for cache sync before processing.
func (w *Watcher) Run(ctx context.Context) error {
	svcHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { w.onService(obj) },
		UpdateFunc: func(_, obj any) { w.onService(obj) },
		DeleteFunc: func(obj any) { w.onServiceDelete(obj) },
	}
	if _, err := w.svcs.AddEventHandler(svcHandler); err != nil {
		return fmt.Errorf("add service handler: %w", err)
	}

	sliceHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { w.onSlice(obj) },
		UpdateFunc: func(_, obj any) { w.onSlice(obj) },
		DeleteFunc: func(obj any) { w.onSlice(obj) },
	}
	if _, err := w.slices.AddEventHandler(sliceHandler); err != nil {
		return fmt.Errorf("add endpointslice handler: %w", err)
	}

	w.factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), w.svcs.HasSynced, w.slices.HasSynced) {
		return fmt.Errorf("informer cache sync failed")
	}
	<-ctx.Done()
	return ctx.Err()
}

// onService recomputes desired state for a changed Service and reconciles each of
// its ports. It first runs the throttled externalTrafficPolicy:Local observability
// Warn (warnExternalLocal) — done HERE, on the single Service-informer goroutine,
// not in reconcileService (which the EndpointSlice informer also drives on a second
// goroutine, where the throttle map would race). Routing is unchanged by the Warn.
func (w *Watcher) onService(obj any) {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		return
	}
	w.warnExternalLocal(svc)
	w.reconcileService(svc)
}

// warnExternalLocal emits a once-per-episode Warn when svc requests
// externalTrafficPolicy:Local on a served NodePort — the one configuration k3sm's
// userspace proxy cannot honor. It reads eTP SOLELY for this signal; routing is
// unaffected (the NodePort path already delivers Cluster semantics). The throttle
// (eTPLocalWarned) fires once per CONTIGUOUS eTP:Local-on-NodePort episode: the
// entry is cleared when the Service is observed no longer in that state (a
// Local->Cluster->Local flip re-warns) and on delete (delete+recreate re-warns, no
// leak).
//
// This is COMPLEMENTARY to k3sm's admission-side VAP
// pkg/policy.EnsureExternalTrafficPolicyLocalWarn: this datapath Warn gives
// node-local observability at the exact point traffic diverges and is
// defense-in-depth for the independent darwin-net module, which must not assume the
// k3sm control plane installed the VAP. It is not the sole surfacing.
//
// CONCURRENCY: called ONLY from onService / onServiceDelete (the single
// Service-informer handler goroutine), so eTPLocalWarned needs no lock. Never call
// this from reconcileService — the EndpointSlice informer drives that on a separate
// goroutine.
func (w *Watcher) warnExternalLocal(svc *corev1.Service) {
	key := svc.Namespace + "/" + svc.Name
	vip, _, _, ok, unhonored := serviceToVIP(svc)
	if !ok || !unhonored {
		// No longer eTP:Local-on-NodePort (or not served): end the episode so a
		// later flip back to Local warns again.
		w.eTPMu.Lock()
		delete(w.eTPLocalWarned, key)
		w.eTPMu.Unlock()
		return
	}
	w.eTPMu.Lock()
	already := w.eTPLocalWarned[key]
	if !already {
		w.eTPLocalWarned[key] = true
	}
	w.eTPMu.Unlock()
	if already {
		return
	}
	var nodePorts []int32
	for _, p := range vip.Ports {
		if p.NodePort != 0 {
			nodePorts = append(nodePorts, p.NodePort)
		}
	}
	w.log.Warn("externalTrafficPolicy:Local requested but not honored: k3sm serves NodePort with Cluster semantics — the userspace splice re-originates from the node mesh-egress /32, so the client source IP is not preserved and node-local endpoint selection is not applied",
		"service", key, "externalTrafficPolicy", "Local", "delivered", "Cluster", "nodePorts", nodePorts)
}

// onServiceDelete tears down every port a deleted Service owned.
func (w *Watcher) onServiceDelete(obj any) {
	svc, ok := toService(obj)
	if !ok {
		return
	}
	// End any eTP:Local warn episode so a delete+recreate warns again (no map leak).
	// Shares the single Service-informer goroutine with onService; eTPMu guards it
	// as defense-in-depth regardless (see the eTPLocalWarned field doc).
	w.eTPMu.Lock()
	delete(w.eTPLocalWarned, svc.Namespace+"/"+svc.Name)
	w.eTPMu.Unlock()
	vip, _, _, ok, _ := serviceToVIP(svc)
	if !ok {
		return
	}
	// Same stripe as reconcileService: a delete racing a slice-driven recompute
	// must not be overtaken by that recompute's already-snapshotted backend set.
	mu := w.serviceStripe(svc.Namespace + "/" + svc.Name)
	mu.Lock()
	defer mu.Unlock()
	for _, p := range vip.Ports {
		w.proxy.ReconcileDelete(PortKey{
			ClusterIP: vip.ClusterIP,
			Port:      p.Port,
			Protocol:  p.Protocol,
		})
	}
}

// onSlice maps a changed EndpointSlice back to its owning Service (via the
// kubernetes.io/service-name label) and reconciles it.
func (w *Watcher) onSlice(obj any) {
	sl, ok := toSlice(obj)
	if !ok {
		return
	}
	svcName := sl.Labels[discoveryv1.LabelServiceName]
	if svcName == "" {
		return
	}
	key := sl.Namespace + "/" + svcName
	item, exists, err := w.svcs.GetStore().GetByKey(key)
	if err != nil || !exists {
		return
	}
	svc, ok := item.(*corev1.Service)
	if !ok {
		return
	}
	w.reconcileService(svc)
}

// reconcileService recomputes each port's backend set from the cached
// EndpointSlices (or the Service's static override) and reconciles it through
// the proxy, carrying the Service's internalTrafficPolicy (so the routing table
// can filter to node-local backends) and its ClientIP session-affinity config.
func (w *Watcher) reconcileService(svc *corev1.Service) {
	vip, policy, affinity, ok, _ := serviceToVIP(svc)
	if !ok {
		return
	}
	key := svc.Namespace + "/" + svc.Name
	// Snapshot and deliver under the Service's stripe so a slower goroutine cannot
	// land an older backend set on top of a newer one (see reconcileMu).
	mu := w.serviceStripe(key)
	mu.Lock()
	defer mu.Unlock()
	slices := w.slicesForService(svc.Namespace, svc.Name)
	for i := range vip.Ports {
		p := vip.Ports[i]
		eps := w.backendsForPort(key, slices, p.Name)
		if err := w.proxy.ReconcilePolicy(vip.ClusterIP, &p, policy, affinity, eps); err != nil {
			w.log.Error("reconcile service port", "service", key, "port", p.Port, "err", err)
		}
	}
}

// backendsForPort resolves one Service port's backend set: the Service's static
// override when one is pinned (WithStaticBackends — the override replaces the
// slice-derived set entirely, so a stray slice for an overridden Service can
// never shadow or split the pinned backend), else the Ready endpoints matched
// from the cached EndpointSlices by port name.
func (w *Watcher) backendsForPort(key string, slices []*discoveryv1.EndpointSlice, portName string) []netv1.Endpoint {
	if eps, ok := w.static[key]; ok {
		return eps
	}
	return endpointsForPort(slices, portName)
}

// reconcileStripes is the width of the per-Service reconcile lock table. It is a
// power of two comfortably above the Service count of a k3sm node, so unrelated
// Services almost never share a stripe, while the table stays a fixed-size array
// with no per-Service allocation and no lifecycle to leak on Service delete.
const reconcileStripes = 32

// serviceStripe returns the reconcile lock guarding the Service key
// "namespace/name". The hash is FNV-1a, inlined to keep the data path
// allocation-free; a collision costs only mutual exclusion between two unrelated
// Services, never correctness.
func (w *Watcher) serviceStripe(key string) *sync.Mutex {
	const (
		fnvOffset32 = 2166136261
		fnvPrime32  = 16777619
	)
	h := uint32(fnvOffset32)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= fnvPrime32
	}
	return &w.reconcileMu[h%reconcileStripes]
}

// slicesForService returns the cached EndpointSlices labeled for the Service.
func (w *Watcher) slicesForService(namespace, name string) []*discoveryv1.EndpointSlice {
	var out []*discoveryv1.EndpointSlice
	for _, item := range w.slices.GetStore().List() {
		sl, ok := item.(*discoveryv1.EndpointSlice)
		if !ok || sl.Namespace != namespace {
			continue
		}
		if sl.Labels[discoveryv1.LabelServiceName] == name {
			out = append(out, sl)
		}
	}
	return out
}

// toService extracts a Service from an informer object, unwrapping a
// DeletedFinalStateUnknown tombstone.
func toService(obj any) (*corev1.Service, bool) {
	if svc, ok := obj.(*corev1.Service); ok {
		return svc, true
	}
	if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		if svc, ok := tomb.Obj.(*corev1.Service); ok {
			return svc, true
		}
	}
	return nil, false
}

// toSlice extracts an EndpointSlice from an informer object, unwrapping a
// DeletedFinalStateUnknown tombstone.
func toSlice(obj any) (*discoveryv1.EndpointSlice, bool) {
	if sl, ok := obj.(*discoveryv1.EndpointSlice); ok {
		return sl, true
	}
	if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		if sl, ok := tomb.Obj.(*discoveryv1.EndpointSlice); ok {
			return sl, true
		}
	}
	return nil, false
}
