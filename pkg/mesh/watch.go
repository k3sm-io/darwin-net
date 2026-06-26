package mesh

import (
	"context"
	"fmt"
	"log/slog"

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

// Watcher drives a Mesh from a MeshPeer informer. On every MeshPeer add, update,
// or delete it recomputes the FULL peer snapshot from the informer cache and calls
// Mesh.Reconcile — a continuous reconcile, never a one-shot startup read — so a
// peer that roams onto a new endpoint or rotates its key reconverges automatically.
// It mirrors the Service proxy's Watcher: correctness comes from the full-snapshot
// reconcile, not from per-event ordering.
type Watcher struct {
	mesh     *Mesh
	informer cache.SharedIndexInformer
	log      *slog.Logger
}

// NewWatcher builds a Watcher over the cluster REST config for the given Mesh. It
// registers the net.k3sm.io/v1 types (netv1.AddToScheme) into a private scheme,
// builds a typed REST client for the MeshPeer GVK, and wires a shared informer
// that yields typed *netv1.MeshPeer objects. It does not start the informer — call
// Run. The MeshPeer is cluster-scoped, so the informer watches all namespaces.
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
	return &Watcher{mesh: mesh, informer: informer, log: log}, nil
}

// Run starts the informer and blocks until ctx is cancelled. It registers an event
// handler that reconciles the full mesh on any MeshPeer change, then waits for the
// cache to sync before returning control to the blocking wait.
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
// the mesh. A reconcile error is logged here, at the boundary that handles it (the
// next event re-drives it); it does not stop the watch.
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
