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

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Watcher drives a Proxy from Kubernetes Service and EndpointSlice informers. It
// is the production watch seam: on every Service or EndpointSlice event it
// recomputes the affected Service's desired state and calls Proxy.Reconcile,
// which routes each port to its single per-VIP worker. The informers' shared
// cache makes the recompute cheap; correctness comes from the proxy's per-key
// serialization, not from event ordering here.
type Watcher struct {
	proxy   *Proxy
	factory informers.SharedInformerFactory
	svcs    cache.SharedIndexInformer
	slices  cache.SharedIndexInformer
	log     *slog.Logger
}

// NewWatcher builds a Watcher over client for the given Proxy. It wires Service
// and EndpointSlice informers but does not start them; call Run.
func NewWatcher(client kubernetes.Interface, proxy *Proxy, log *slog.Logger) *Watcher {
	if log == nil {
		log = slog.Default()
	}
	f := informers.NewSharedInformerFactory(client, 0)
	return &Watcher{
		proxy:   proxy,
		factory: f,
		svcs:    f.Core().V1().Services().Informer(),
		slices:  f.Discovery().V1().EndpointSlices().Informer(),
		log:     log,
	}
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
// its ports.
func (w *Watcher) onService(obj any) {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		return
	}
	w.reconcileService(svc)
}

// onServiceDelete tears down every port a deleted Service owned.
func (w *Watcher) onServiceDelete(obj any) {
	svc, ok := toService(obj)
	if !ok {
		return
	}
	vip, _, ok := serviceToVIP(svc)
	if !ok {
		return
	}
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
// EndpointSlices and reconciles it through the proxy, carrying the Service's
// internalTrafficPolicy so the routing table can filter to node-local backends.
func (w *Watcher) reconcileService(svc *corev1.Service) {
	vip, policy, ok := serviceToVIP(svc)
	if !ok {
		return
	}
	slices := w.slicesForService(svc.Namespace, svc.Name)
	for i := range vip.Ports {
		p := vip.Ports[i]
		eps := endpointsForPort(slices, p.Name)
		if err := w.proxy.ReconcilePolicy(vip.ClusterIP, &p, policy, eps); err != nil {
			w.log.Error("reconcile service port", "service", svc.Namespace+"/"+svc.Name, "port", p.Port, "err", err)
		}
	}
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
