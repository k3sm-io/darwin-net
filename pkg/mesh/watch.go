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

// meshResyncPeriod is how often the MeshPeer informer re-delivers its full cache
// through the event handler even when no MeshPeer changed, so the watcher
// periodically re-applies the desired mesh state. It is the mesh's reconvergence
// floor after the root netd helper restarts (launchctl kickstart -k io.k3sm.netd):
// the utun/wireguard device and its up/route state live IN the netd process and are
// lost on a restart, while this watcher is a long-lived unprivileged client that
// tracks no device generation — so without a periodic resync nothing re-issues
// ConfigureMesh until the next unrelated MeshPeer change, and the cross-node mesh
// would stay DOWN indefinitely. 30s bounds reconvergence to <=30s after a helper
// restart; the cost is negligible because the MeshPeer set is small (one per
// cluster node, cluster-scoped) and Device.Apply is an idempotent full-resync UAPI
// write, so a resync with no change is a cheap re-assertion, not new state.
const meshResyncPeriod = 30 * time.Second

// Watcher drives a Mesh from a MeshPeer informer. On every MeshPeer add, update,
// or delete it recomputes the FULL peer snapshot from the informer cache and calls
// Mesh.Reconcile — a continuous reconcile, never a one-shot startup read — so a
// peer that roams onto a new endpoint or rotates its key reconverges automatically.
// It mirrors the Service proxy's Watcher: correctness comes from the full-snapshot
// reconcile, not from per-event ordering.
//
// The informer is built with a bounded resync period (meshResyncPeriod) so the same
// full-snapshot reconcile also fires periodically with no MeshPeer change; that is
// what reconverges the utun/wireguard after the root netd helper restarts and drops
// the in-process device, without waiting for an unrelated MeshPeer event to arrive.
type Watcher struct {
	mesh         *Mesh
	informer     cache.SharedIndexInformer
	resyncPeriod time.Duration
	log          *slog.Logger
}

// NewWatcher builds a Watcher over the cluster REST config for the given Mesh. It
// registers the net.k3sm.io/v1 types (netv1.AddToScheme) into a private scheme,
// builds a typed REST client for the MeshPeer GVK, and wires a shared informer
// that yields typed *netv1.MeshPeer objects with a bounded resync (meshResyncPeriod)
// so the reconcile re-fires periodically. It does not start the informer — call Run.
// The MeshPeer is cluster-scoped, so the informer watches all namespaces.
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
	informer := cache.NewSharedIndexInformer(lw, &netv1.MeshPeer{}, meshResyncPeriod, cache.Indexers{})
	return &Watcher{mesh: mesh, informer: informer, resyncPeriod: meshResyncPeriod, log: log}, nil
}

// Run starts the informer and blocks until ctx is cancelled. It registers an event
// handler that reconciles the full mesh on any MeshPeer change AND on the informer's
// periodic resync (every meshResyncPeriod the cache is re-delivered through
// UpdateFunc with no change), then waits for the cache to sync before returning
// control to the blocking wait. The periodic resync is what reconverges the mesh
// after a netd restart without a MeshPeer event.
func (w *Watcher) Run(ctx context.Context) error {
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { w.resync(ctx) },
		UpdateFunc: func(_, _ any) { w.resync(ctx) },
		DeleteFunc: func(any) { w.resync(ctx) },
	}
	if _, err := w.informer.AddEventHandler(handler); err != nil {
		return fmt.Errorf("add meshpeer handler: %w", err)
	}
	go w.informer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), w.informer.HasSynced) {
		return fmt.Errorf("meshpeer informer cache sync failed")
	}
	<-ctx.Done()
	return ctx.Err()
}

// resync recomputes the full peer snapshot from the informer cache and reconciles
// the mesh. It is driven both by MeshPeer events and by the informer's periodic
// resync (meshResyncPeriod), so it re-asserts the desired state even when nothing
// changed — that is the post-netd-restart reconvergence path. A reconcile error is
// logged here, at the boundary that handles it (the next event or resync re-drives
// it); it does not stop the watch.
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
