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

package ingress

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// SecretRef names one tls[] Secret referenced by a reconciled Ingress, with the
// hosts it terminates. The Watcher SURFACES these to the host via OnTLSSecrets;
// the HOST fetches the Secrets (with its own scoped client) and installs parsed
// certificates into the CertResolver — this package never holds a Secrets
// client and never sees Secret bytes on this path.
type SecretRef struct {
	Namespace string
	Name      string
	// Hosts are the SNI hosts the Secret's certificate should serve, sorted.
	Hosts []string
}

// WatcherConfig configures a Watcher.
type WatcherConfig struct {
	// ClassName filters reconciliation to Ingresses whose spec.ingressClassName
	// equals it exactly. An Ingress with a nil or different class is ignored —
	// the Watcher reconciles ONLY its class.
	ClassName string
	// OnTLSSecrets, if set, is invoked after every reconcile with the sorted,
	// deduplicated tls[] Secret references of the reconciled Ingresses. It is
	// called outside the Watcher's lock; implementations may call back into the
	// CertResolver freely.
	OnTLSSecrets func(refs []SecretRef)
}

// Watcher drives a RouteTable from class-filtered networking/v1 Ingress
// informers. On every Ingress or Service event it recomputes the FULL rule set
// from the informer caches and swaps it into the table — correctness comes from
// the table's atomic snapshot, not from event ordering. Services are watched
// too because resolving an Ingress backend needs the Service object twice over:
// the ClusterIP VIP to dial, and the port number when the backend names its
// port (port-by-NAME is defined on the Service's spec.ports).
type Watcher struct {
	table   *RouteTable
	cfg     WatcherConfig
	factory informers.SharedInformerFactory
	ings    cache.SharedIndexInformer
	svcs    cache.SharedIndexInformer
	log     *slog.Logger

	// resyncMu serializes resync so two informer goroutines (Ingress + Service)
	// cannot interleave a stale table.Update over a fresher one. OnTLSSecrets is
	// invoked after the lock is released (never under it).
	resyncMu sync.Mutex
}

// NewWatcher builds a Watcher over client feeding table. It wires Ingress and
// Service informers but does not start them; call Run.
func NewWatcher(client kubernetes.Interface, table *RouteTable, cfg WatcherConfig, log *slog.Logger) *Watcher {
	if log == nil {
		log = slog.Default()
	}
	f := informers.NewSharedInformerFactory(client, 0)
	return &Watcher{
		table:   table,
		cfg:     cfg,
		factory: f,
		ings:    f.Networking().V1().Ingresses().Informer(),
		svcs:    f.Core().V1().Services().Informer(),
		log:     log,
	}
}

// Run starts the informers and blocks until ctx is cancelled, resyncing the
// table on every Ingress or Service event after the caches sync.
func (w *Watcher) Run(ctx context.Context) error {
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { w.resync() },
		UpdateFunc: func(_, _ any) { w.resync() },
		DeleteFunc: func(any) { w.resync() },
	}
	if _, err := w.ings.AddEventHandler(handler); err != nil {
		return fmt.Errorf("add ingress handler: %w", err)
	}
	if _, err := w.svcs.AddEventHandler(handler); err != nil {
		return fmt.Errorf("add service handler: %w", err)
	}
	w.factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), w.ings.HasSynced, w.svcs.HasSynced) {
		return fmt.Errorf("informer cache sync failed")
	}
	<-ctx.Done()
	return ctx.Err()
}

// resync recomputes the rule set from the cached Ingresses of w's class and
// swaps it into the table, then surfaces the tls[] Secret references.
func (w *Watcher) resync() {
	w.resyncMu.Lock()
	rules, def, refs := w.desiredState()
	w.table.Update(rules, def)
	w.resyncMu.Unlock()
	// Callback outside the lock (go-standards concurrency discipline): the host
	// may synchronously fetch Secrets and install certificates.
	if w.cfg.OnTLSSecrets != nil {
		w.cfg.OnTLSSecrets(refs)
	}
}

// desiredState converts every cached class-matched Ingress into routing rules,
// a default backend, and the union of tls[] Secret references. Ingresses are
// processed in sorted namespace/name order so the outcome is deterministic when
// objects overlap; in particular, when several Ingresses set
// spec.defaultBackend the lexicographically-first one wins (documented tie
// break, mirrored by the acceptance test).
func (w *Watcher) desiredState() ([]Rule, *Backend, []SecretRef) {
	var ingresses []*networkingv1.Ingress
	for _, item := range w.ings.GetStore().List() {
		ing, ok := item.(*networkingv1.Ingress)
		if !ok || ing.Spec.IngressClassName == nil || *ing.Spec.IngressClassName != w.cfg.ClassName {
			continue
		}
		ingresses = append(ingresses, ing)
	}
	sort.Slice(ingresses, func(i, j int) bool {
		if ingresses[i].Namespace != ingresses[j].Namespace {
			return ingresses[i].Namespace < ingresses[j].Namespace
		}
		return ingresses[i].Name < ingresses[j].Name
	})

	var (
		rules  []Rule
		def    *Backend
		refMap = map[string]*SecretRef{}
	)
	for _, ing := range ingresses {
		name := ing.Namespace + "/" + ing.Name
		if def == nil && ing.Spec.DefaultBackend != nil {
			if be, ok := w.resolveBackend(ing.Namespace, name, ing.Spec.DefaultBackend); ok {
				def = &be
			}
		}
		for i := range ing.Spec.Rules {
			rules = append(rules, w.rulesFor(ing, &ing.Spec.Rules[i])...)
		}
		for _, t := range ing.Spec.TLS {
			if t.SecretName == "" {
				continue
			}
			key := ing.Namespace + "/" + t.SecretName
			ref, ok := refMap[key]
			if !ok {
				ref = &SecretRef{Namespace: ing.Namespace, Name: t.SecretName}
				refMap[key] = ref
			}
			ref.Hosts = append(ref.Hosts, t.Hosts...)
		}
	}

	refs := make([]SecretRef, 0, len(refMap))
	for _, r := range refMap {
		sort.Strings(r.Hosts)
		r.Hosts = dedupSorted(r.Hosts)
		refs = append(refs, *r)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Namespace != refs[j].Namespace {
			return refs[i].Namespace < refs[j].Namespace
		}
		return refs[i].Name < refs[j].Name
	})
	return rules, def, refs
}

// rulesFor converts one Ingress rule into RouteTable rules. Wildcard hosts
// (*.example.com) are DEFERRED — the rule is skipped with a Debug so the gap is
// observable; exact-host and hostless rules are converted. A nil pathType or
// ImplementationSpecific is treated as Prefix (documented: k3sm's
// implementation-specific interpretation IS Prefix matching).
func (w *Watcher) rulesFor(ing *networkingv1.Ingress, rule *networkingv1.IngressRule) []Rule {
	name := ing.Namespace + "/" + ing.Name
	if strings.Contains(rule.Host, "*") {
		w.log.Debug("wildcard ingress host deferred, rule skipped", "ingress", name, "host", rule.Host)
		return nil
	}
	if rule.HTTP == nil {
		return nil
	}
	var out []Rule
	for i := range rule.HTTP.Paths {
		p := &rule.HTTP.Paths[i]
		be, ok := w.resolveBackend(ing.Namespace, name, &p.Backend)
		if !ok {
			continue
		}
		pt := PathTypePrefix
		if p.PathType != nil && *p.PathType == networkingv1.PathTypeExact {
			pt = PathTypeExact
		}
		out = append(out, Rule{
			Host:     strings.ToLower(rule.Host),
			Path:     p.Path,
			PathType: pt,
			Backend:  be,
		})
	}
	return out
}

// resolveBackend resolves an IngressBackend to the dialable Service ClusterIP
// VIP + Service port, via the cached Service object (needed for BOTH the VIP
// and port-by-name — a named port is defined on the Service's spec.ports). An
// unresolvable backend (resource backend, missing Service, headless/invalid
// ClusterIP, unknown port name) is skipped with a Warn; a later Service event
// resyncs it in.
func (w *Watcher) resolveBackend(namespace, ingName string, b *networkingv1.IngressBackend) (Backend, bool) {
	if b.Service == nil {
		w.log.Warn("ingress backend is not a service backend, skipped", "ingress", ingName)
		return Backend{}, false
	}
	item, exists, err := w.svcs.GetStore().GetByKey(namespace + "/" + b.Service.Name)
	if err != nil || !exists {
		w.log.Warn("ingress backend service not found, rule skipped until it appears",
			"ingress", ingName, "service", namespace+"/"+b.Service.Name)
		return Backend{}, false
	}
	svc, ok := item.(*corev1.Service)
	if !ok {
		return Backend{}, false
	}
	vip, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil {
		w.log.Warn("ingress backend service has no dialable clusterIP, rule skipped",
			"ingress", ingName, "service", namespace+"/"+b.Service.Name, "clusterIP", svc.Spec.ClusterIP)
		return Backend{}, false
	}
	port := b.Service.Port.Number
	if b.Service.Port.Name != "" {
		port = 0
		for i := range svc.Spec.Ports {
			if svc.Spec.Ports[i].Name == b.Service.Port.Name {
				port = svc.Spec.Ports[i].Port
				break
			}
		}
		if port == 0 {
			w.log.Warn("ingress backend port name not found on service, rule skipped",
				"ingress", ingName, "service", namespace+"/"+b.Service.Name, "portName", b.Service.Port.Name)
			return Backend{}, false
		}
	}
	if port <= 0 || port > 65535 {
		w.log.Warn("ingress backend port out of range, rule skipped",
			"ingress", ingName, "service", namespace+"/"+b.Service.Name, "port", port)
		return Backend{}, false
	}
	return Backend{VIP: vip, Port: uint16(port)}, true
}

// dedupSorted removes adjacent duplicates from a sorted slice in place.
func dedupSorted(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}
