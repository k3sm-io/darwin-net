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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/netd/wire"
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
// because Device.Apply is idempotent (an unchanged peer set writes nothing to wireguard
// and the kernel routes are only re-verified), so a resync with no change is a cheap re-assertion, not new state.
//
// The period drives the WATCHER'S OWN ticker (Watcher.reconcileLoop), not the informer's
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
	client       rest.Interface
	resyncPeriod time.Duration
	log          *slog.Logger

	// kick is the one-slot edge trigger. Senders never block (trigger); the only
	// receiver is reconcileLoop. A full slot means a pass is already owed, so a
	// further send is dropped, not queued — that is the coalescing.
	kick chan struct{}
	// statusKick is the status writer's one-slot edge trigger, armed by every
	// successful reconcile pass when patchStatus is set and drained only by
	// statusLoop. It coalesces exactly like kick: a pass that lands while a
	// status pass runs owes one further status pass, never a queue of them.
	statusKick chan struct{}

	// patchStatus, when set (WithHandshakeStatus), merge-patches a MeshPeer's
	// status subresource; nil writes no status. It is a field so a test can
	// record the writes with no apiserver.
	patchStatus func(ctx context.Context, name string, patch []byte) error
	// helperTooOldLogged records that the "netd helper too old" outcome has
	// been logged, so it is reported once per episode instead of every pass. It
	// is touched only on statusLoop's goroutine (via writeHandshakeStatus), so
	// it needs no lock; a successful read clears it.
	helperTooOldLogged bool
}

// WatcherOption configures a Watcher.
type WatcherOption func(*Watcher)

// WithHandshakeStatus makes the watcher write each MeshPeer's
// status.lastHandshakeTime from this node's own wireguard view after every
// reconcile pass. Only the control-plane node sets it: the status is one value
// per MeshPeer, so it records the server's view of each peer, and the server's
// identity is the one that may write MeshPeers. A worker's watcher stays
// read-only.
func WithHandshakeStatus() WatcherOption {
	return func(w *Watcher) { w.patchStatus = w.restPatchStatus }
}

// NewWatcher builds a Watcher over the cluster REST config for the given Mesh. It
// registers the net.k3sm.io/v1 types (netv1.AddToScheme) into a private scheme,
// builds a typed REST client for the MeshPeer GVK, and wires a shared informer
// that yields typed *netv1.MeshPeer objects. The informer takes resync period 0 —
// the periodic re-assertion is the watcher's own ticker (meshResyncPeriod), which
// reconciles once per tick instead of once per cached peer. It does not start the
// informer — call Run. The MeshPeer is cluster-scoped, so the informer watches all
// namespaces.
func NewWatcher(cfg *rest.Config, mesh *Mesh, log *slog.Logger, opts ...WatcherOption) (*Watcher, error) {
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
	w := &Watcher{mesh: mesh, informer: informer, client: client, resyncPeriod: meshResyncPeriod, log: log, kick: make(chan struct{}, 1), statusKick: make(chan struct{}, 1)}
	for _, o := range opts {
		o(w)
	}
	return w, nil
}

// restPatchStatus merge-patches the named MeshPeer's status subresource.
func (w *Watcher) restPatchStatus(ctx context.Context, name string, patch []byte) error {
	return w.client.Patch(types.MergePatchType).
		Resource(meshPeerResource).
		Name(name).
		SubResource("status").
		Body(patch).
		Do(ctx).
		Error()
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
//
// When the watcher writes status (WithHandshakeStatus), the loop also owns the
// status writer's goroutine, statusLoop: it starts it, and on ctx cancellation
// it waits for it to exit before returning, so no status write outlives the
// watch.
func (w *Watcher) reconcileLoop(ctx context.Context, ticks <-chan time.Time) error {
	if w.patchStatus != nil {
		statusDone := make(chan struct{})
		go func() {
			defer close(statusDone)
			w.statusLoop(ctx)
		}()
		defer func() { <-statusDone }()
	}
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
//
// The coalescing above also coalesces retries: a failed Reconcile does not
// re-arm the trigger on its own, so a burst of N events that lands during a
// failing pass is still one further attempt, where before coalescing it would
// have been N. The periodic tick is the floor either way, so the worst-case
// time to reconverge after a failure is unchanged; re-arming on failure without
// a backoff would instead turn a persistent error into a hot loop.
//
// A successful pass does not write MeshPeer status itself: it arms statusKick
// and returns, so the next peer-set change is reconciled without waiting on
// the apiserver.
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
		return
	}
	if w.patchStatus != nil {
		w.triggerStatus()
	}
}

// triggerStatus arms the status writer's one-slot trigger without blocking. A
// full slot means a status pass is already owed and will read the informer
// cache after this call returns, so dropping the send loses nothing.
func (w *Watcher) triggerStatus() {
	select {
	case w.statusKick <- struct{}{}:
	default:
	}
}

// statusLoop is the single consumer of statusKick: it runs one status pass per
// drain until ctx is cancelled. It is the status writes' own goroutine, so the
// reconcile loop never waits on the apiserver: a peer-set change is reconciled,
// and its AllowedIPs programmed, while a slow status write is still pending.
func (w *Watcher) statusLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.statusKick:
			w.writeHandshakeStatus(ctx)
		}
	}
}

// writeHandshakeStatus writes status.lastHandshakeTime on every cached MeshPeer
// whose handshake, as this node's wireguard device reports it, is newer than
// the recorded one. The status field has second precision, so the comparison
// is at whole seconds and an unchanged handshake writes nothing; a pass with no
// new handshake makes no API call at all. Only a newer time is written, so two
// writers (an HA control plane) converge on the latest handshake either saw
// instead of overwriting each other. A peer with no handshake, this node's own
// MeshPeer, and a failed device read write nothing. Each write runs under its
// own statusWriteTimeout, and each failed write is logged and retried by the
// next pass. It runs on statusLoop's goroutine and reads the informer cache
// itself, so it always writes against the latest MeshPeers.
func (w *Watcher) writeHandshakeStatus(ctx context.Context) {
	seen, err := w.mesh.PeerHandshakes(ctx)
	switch {
	case err == nil:
		w.helperTooOldLogged = false
	case errors.Is(err, ErrNoHandshakeReader):
		w.log.Debug("mesh device reports no handshakes; MeshPeer status not written", "err", err)
		return
	case errors.Is(err, wire.ErrHelperTooOld):
		if !w.helperTooOldLogged {
			w.log.Warn("the netd helper is too old to report mesh handshakes; MeshPeer status is not written until it is upgraded", "err", err)
			w.helperTooOldLogged = true
		}
		return
	default:
		w.log.Warn("read mesh peer handshakes", "err", err)
		return
	}
	for _, obj := range w.informer.GetStore().List() {
		mp, ok := obj.(*netv1.MeshPeer)
		if !ok {
			continue
		}
		t, ok := seen[mp.Spec.NodeName]
		if !ok || t.IsZero() {
			continue
		}
		at := t.UTC().Truncate(time.Second)
		if cur := mp.Status.LastHandshakeTime; cur != nil && !at.After(cur.Time) {
			continue
		}
		patch, err := handshakeStatusPatch(at)
		if err != nil {
			w.log.Error("encode MeshPeer status patch", "meshpeer", mp.Name, "err", err)
			continue
		}
		if err := w.patchOneStatus(ctx, mp.Name, patch); err != nil {
			w.log.Warn("write MeshPeer status.lastHandshakeTime", "meshpeer", mp.Name, "err", err)
			continue
		}
		w.log.Debug("wrote MeshPeer status.lastHandshakeTime", "meshpeer", mp.Name, "lastHandshakeTime", at)
	}
}

// patchOneStatus writes one MeshPeer status patch under statusWriteTimeout,
// so a slow apiserver delays only that write, never the rest of the pass.
func (w *Watcher) patchOneStatus(ctx context.Context, name string, patch []byte) error {
	ctx, cancel := context.WithTimeout(ctx, statusWriteTimeout)
	defer cancel()
	return w.patchStatus(ctx, name, patch)
}

// handshakeStatusPatch is the merge patch that sets status.lastHandshakeTime
// to at and touches no other status field.
func handshakeStatusPatch(at time.Time) ([]byte, error) {
	mt := metav1.NewTime(at)
	return json.Marshal(map[string]any{"status": map[string]any{"lastHandshakeTime": &mt}})
}
