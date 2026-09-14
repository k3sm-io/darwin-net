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
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	netv1 "k3sm.io/apis/net/v1"
)

// meshPeerResource is the MeshPeer CRD resource name within net.k3sm.io/v1.
const meshPeerResource = "meshpeers"

// meshResyncPeriod is how often the watcher re-applies the desired mesh state even
// when no MeshPeer changed. It is the mesh's reconvergence floor after the root netd
// helper restarts (launchctl kickstart -k io.k3sm.netd): the utun/wireguard device
// and its up/route state live IN the netd process and are lost on a restart, while
// this watcher is a long-lived unprivileged client that tracks no device generation —
// so without a periodic resync nothing re-issues ConfigureMesh until the next
// unrelated MeshPeer change, and the cross-node mesh would stay DOWN indefinitely.
// 30s bounds reconvergence to <=30s after a helper restart; the cost is negligible
// because Device.Apply is an idempotent full-resync UAPI write, so a resync with no
// change is a cheap re-assertion, not new state.
//
// The period drives the WATCHER'S OWN ticker (Watcher.resyncLoop), not the informer's
// resync. An informer resync re-delivers the whole cache through UpdateFunc, which
// would fire one full Reconcile per cached MeshPeer — N ConfigureMesh RPCs to netd
// per tick on an N-node cluster — for a single re-assertion of one full snapshot. The
// informer is therefore built with resync 0 and the ticker calls resync exactly once
// per period regardless of node count.
const meshResyncPeriod = 30 * time.Second

// Watcher drives a Mesh from a MeshPeer informer. On every MeshPeer add, real update,
// or delete it recomputes the FULL peer snapshot from the informer cache and calls
// Mesh.Reconcile — a continuous reconcile, never a one-shot startup read — so a
// peer that roams onto a new endpoint or rotates its key reconverges automatically.
// It mirrors the Service proxy's Watcher: correctness comes from the full-snapshot
// reconcile, not from per-event ordering.
//
// The same full-snapshot reconcile also fires periodically with no MeshPeer change,
// driven by the watcher's own ticker at resyncPeriod; that is what reconverges the
// utun/wireguard after the root netd helper restarts and drops the in-process device,
// without waiting for an unrelated MeshPeer event to arrive.
//
// Events and ticks do not reconcile inline. Each one arms kick, a one-slot edge
// trigger, and a single loop (reconcileLoop) drains it and runs one full-snapshot
// pass per drain. So the informer's delivery goroutine never blocks on the device —
// the pass holds Mesh.mu across a ConfigureMesh RPC to the root netd helper, or
// across an IpcSet plus a kernel route read-back — and any burst of events that
// lands while a pass is running (the initial list of an N-node cluster, a rolling
// endpoint change) collapses into at most one further pass. Nothing is lost by the
// collapse: a pass reads the whole informer cache, and the slot is drained BEFORE
// the cache is read, so an event that arrives after the read re-arms the slot and
// gets its own pass.
type Watcher struct {
	mesh         *Mesh
	informer     cache.SharedIndexInformer
	resyncPeriod time.Duration
	log          *slog.Logger

	// kick is the one-slot edge trigger. Senders never block (trigger); the only
	// receiver is reconcileLoop. A full slot means a pass is already owed, so a
	// further send is dropped, not queued — that is the coalescing.
	kick chan struct{}
}

// NewWatcher builds a Watcher over the cluster REST config for the given Mesh. It
// registers the net.k3sm.io/v1 types (netv1.AddToScheme) into a private scheme,
// builds a typed REST client for the MeshPeer GVK, and wires a shared informer
// that yields typed *netv1.MeshPeer objects. The informer takes resync period 0 —
// the periodic re-assertion is the watcher's own ticker (meshResyncPeriod), which
// reconciles once per tick instead of once per cached peer. It does not start the
// informer — call Run. The MeshPeer is cluster-scoped, so the informer watches all
// namespaces.
func NewWatcher(cfg *rest.Config, mesh *Mesh, log *slog.Logger) (*Watcher, error) {
	if log == nil {
		log = slog.Default()
	}
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register net.k3sm.io scheme: %w", err)
	}
	codecs := serializer.NewCodecFactory(scheme)

	rc := rest.CopyConfig(cfg)
	rc.GroupVersion = &netv1.SchemeGroupVersion
	rc.APIPath = "/apis"
	rc.NegotiatedSerializer = codecs.WithoutConversion()
	client, err := rest.RESTClientFor(rc)
	if err != nil {
		return nil, fmt.Errorf("build MeshPeer REST client: %w", err)
	}

	lw := cache.NewListWatchFromClient(client, meshPeerResource, metav1.NamespaceAll, fields.Everything())
	informer := cache.NewSharedIndexInformer(lw, &netv1.MeshPeer{}, 0, cache.Indexers{})
	return &Watcher{mesh: mesh, informer: informer, resyncPeriod: meshResyncPeriod, log: log, kick: make(chan struct{}, 1)}, nil
}

// Run starts the informer and blocks until ctx is cancelled. It registers an event
// handler that arms the trigger on any real MeshPeer change, waits for the cache to
// sync, then runs the reconcile loop, which drains the trigger and also drives one
// full resync per meshResyncPeriod tick — the path that reconverges the mesh after
// a netd restart without a MeshPeer event. The adds delivered by the initial list
// arm the trigger while the cache is still syncing, so the first pass runs once the
// loop starts, against the synced cache, instead of once per listed peer.
func (w *Watcher) Run(ctx context.Context) error {
	if _, err := w.informer.AddEventHandler(w.handler()); err != nil {
		return fmt.Errorf("add meshpeer handler: %w", err)
	}
	go w.informer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), w.informer.HasSynced) {
		return fmt.Errorf("meshpeer informer cache sync failed")
	}
	ticker := time.NewTicker(w.resyncPeriod)
	defer ticker.Stop()
	return w.reconcileLoop(ctx, ticker.C)
}

// handler is the informer event handler: an add or a delete always arms the
// trigger, and an update arms it only when the MeshPeer actually changed
// (meshPeerChanged). The update guard keeps a re-delivery of an unchanged object —
// from a relist, or from an informer resync should one ever be configured — from
// arming a pass at all. The handlers do no reconcile work themselves and never
// block: the informer's delivery goroutine is back to the next event as soon as
// the (non-blocking) send returns.
func (w *Watcher) handler() cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(any) { w.trigger() },
		UpdateFunc: func(oldObj, newObj any) {
			if !meshPeerChanged(oldObj, newObj) {
				return
			}
			w.trigger()
		},
		DeleteFunc: func(any) { w.trigger() },
	}
}

// trigger arms the one-slot edge trigger without blocking. If the slot is already
// full a pass is already owed and will read the informer cache after this call
// returns, so dropping the send loses nothing.
func (w *Watcher) trigger() {
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

// meshPeerChanged reports whether an informer update carries a real MeshPeer change,
// by comparing ResourceVersion — the apiserver's own change token, which advances on
// every write and is identical on a re-delivery of the same object. Anything that is
// not a typed *netv1.MeshPeer pair (a tombstone, an unexpected type) counts as
// changed, so the guard fails toward reconciling: a redundant full-snapshot reconcile
// is idempotent, a missed one leaves the mesh stale.
func meshPeerChanged(oldObj, newObj any) bool {
	oldPeer, ok := oldObj.(*netv1.MeshPeer)
	if !ok {
		return true
	}
	newPeer, ok := newObj.(*netv1.MeshPeer)
	if !ok {
		return true
	}
	return oldPeer.ResourceVersion != newPeer.ResourceVersion
}

// reconcileLoop is the single consumer of the trigger: it runs one full-snapshot
// resync per drain until ctx is cancelled, returning ctx.Err(). A tick arms the
// same trigger rather than reconciling directly, so a tick that lands during a
// burst of events folds into the pass those events already owe; one tick with a
// quiet cluster is still exactly one reconcile no matter how many MeshPeers are
// cached. The receive from kick happens before resync reads the informer cache,
// which is what makes a drop in trigger safe. ticks is a parameter so the loop is
// drivable in a test without waiting a real period.
func (w *Watcher) reconcileLoop(ctx context.Context, ticks <-chan time.Time) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticks:
			w.trigger()
		case <-w.kick:
			w.resync(ctx)
		}
	}
}

// resync recomputes the full peer snapshot from the informer cache and reconciles
// the mesh. It runs only on reconcileLoop's goroutine, driven both by MeshPeer
// events and by the periodic ticker (meshResyncPeriod) through the trigger, so it
// re-asserts the desired state even when nothing changed — that is the
// post-netd-restart reconvergence path. A reconcile error is logged here, at the
// boundary that handles it (the next event or tick re-drives it); it does not stop
// the watch.
func (w *Watcher) resync(ctx context.Context) {
	store := w.informer.GetStore().List()
	specs := make([]netv1.MeshPeerSpec, 0, len(store))
	for _, obj := range store {
		mp, ok := obj.(*netv1.MeshPeer)
		if !ok {
			continue
		}
		specs = append(specs, mp.Spec)
	}
	if err := w.mesh.Reconcile(ctx, specs); err != nil {
		w.log.Error("reconcile mesh from watch", "peers", len(specs), "err", err)
	}
}
