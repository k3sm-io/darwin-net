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
	"net/netip"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// policyRecomputeDebounce coalesces bursts of NetworkPolicy/Pod/Namespace informer
// events into one full recompute: an event arms a fixed (non-resetting) timer and
// every further event inside the window is absorbed, so convergence latency is
// bounded by informer propagation + this window even under sustained churn.
const policyRecomputeDebounce = 100 * time.Millisecond

// PolicyWatcher resolves NetworkPolicies into the PolicyTable's concrete verdict
// state. It is the selector-aware half of the M10.4 L4 subset: it watches
// NetworkPolicies, Pods, AND Namespaces (namespaceSelector peers match on
// namespace LABELS, so namespace objects are load-bearing), and on any event
// debounce-recomputes the FULL resolved state — every policy's selected backend
// pod IPs, each ingress rule's allowed source /32 set and port set, and the
// cluster-wide known-pod-IP attribution set — then installs it atomically via
// PolicyTable.Update.
//
// Full recompute (not incremental diffing) is deliberate: k3sm clusters are a
// handful of Macs with tens-to-hundreds of pods, so an O(policies × pods) pass per
// debounced burst is microseconds, and wholesale replacement makes the table state
// trivially consistent (no cross-event bookkeeping to corrupt).
//
// Fail-open before sync: the table starts empty (allow everything) and Run
// installs the first resolved state only after WaitForCacheSync, so a restarting
// proxy never denies on a partial cache; convergence after an API change is
// bounded by informer latency + policyRecomputeDebounce.
type PolicyWatcher struct {
	table      *PolicyTable
	factory    informers.SharedInformerFactory
	policies   cache.SharedIndexInformer
	pods       cache.SharedIndexInformer
	namespaces cache.SharedIndexInformer
	log        *slog.Logger

	// kick coalesces informer events into the debounced recompute loop; buffered
	// size 1 so a burst collapses to one pending recompute (poke never blocks an
	// informer handler goroutine).
	kick chan struct{}

	// warnedPolicies throttles the once-per-policy honest-ceiling Warn ("VIP-
	// mediated ingress only; direct pod-IP traffic bypasses") keyed by ns/name,
	// cleared on policy delete so a delete+recreate re-warns (no leak). It is
	// touched from the single recompute goroutine and the policy informer's delete
	// handler, so warnMu guards it (mirroring the Watcher.eTPMu defense-in-depth:
	// an unguarded map write across goroutines is a fatal runtime throw).
	warnMu         sync.Mutex
	warnedPolicies map[string]bool
}

// NewPolicyWatcher builds a PolicyWatcher over client feeding table. It wires
// NetworkPolicy, Pod, and Namespace informers but does not start them; call Run.
func NewPolicyWatcher(client kubernetes.Interface, table *PolicyTable, log *slog.Logger) *PolicyWatcher {
	if log == nil {
		log = slog.Default()
	}
	f := informers.NewSharedInformerFactory(client, 0)
	return &PolicyWatcher{
		table:          table,
		factory:        f,
		policies:       f.Networking().V1().NetworkPolicies().Informer(),
		pods:           f.Core().V1().Pods().Informer(),
		namespaces:     f.Core().V1().Namespaces().Informer(),
		log:            log,
		kick:           make(chan struct{}, 1),
		warnedPolicies: make(map[string]bool),
	}
}

// Run starts the informers, waits for cache sync (the table stays empty —
// allow-everything — until then, the documented fail-open), installs the first
// resolved state, and then debounce-recomputes on every NetworkPolicy/Pod/
// Namespace event until ctx is cancelled.
func (w *PolicyWatcher) Run(ctx context.Context) error {
	poke := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { w.poke() },
		UpdateFunc: func(_, _ any) { w.poke() },
		DeleteFunc: func(any) { w.poke() },
	}
	polHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { w.poke() },
		UpdateFunc: func(_, _ any) { w.poke() },
		DeleteFunc: func(obj any) { w.onPolicyDelete(obj); w.poke() },
	}
	if _, err := w.policies.AddEventHandler(polHandler); err != nil {
		return fmt.Errorf("add networkpolicy handler: %w", err)
	}
	if _, err := w.pods.AddEventHandler(poke); err != nil {
		return fmt.Errorf("add pod handler: %w", err)
	}
	if _, err := w.namespaces.AddEventHandler(poke); err != nil {
		return fmt.Errorf("add namespace handler: %w", err)
	}

	w.factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), w.policies.HasSynced, w.pods.HasSynced, w.namespaces.HasSynced) {
		return fmt.Errorf("networkpolicy informer cache sync failed")
	}
	// First authoritative install: only after sync, so the empty (allow-everything)
	// table is never replaced by a verdict computed from a partial cache.
	w.recompute()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-w.kick:
			// Fixed debounce window: absorb the burst, then recompute once. The timer
			// is NOT reset on further events, so sustained churn cannot starve the
			// recompute — worst-case staleness is one debounce window.
			timer := time.NewTimer(policyRecomputeDebounce)
		drain:
			for {
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-w.kick:
				case <-timer.C:
					break drain
				}
			}
			w.recompute()
		}
	}
}

// poke coalesces an informer event into the debounce loop without ever blocking
// the informer handler goroutine.
func (w *PolicyWatcher) poke() {
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

// onPolicyDelete ends a deleted policy's once-per-policy warn episode so a
// delete+recreate warns again (and the map never leaks entries).
func (w *PolicyWatcher) onPolicyDelete(obj any) {
	pol, ok := toNetworkPolicy(obj)
	if !ok {
		return
	}
	w.warnMu.Lock()
	delete(w.warnedPolicies, pol.Namespace+"/"+pol.Name)
	w.warnMu.Unlock()
}

// recompute resolves EVERY NetworkPolicy against the cached Pods and Namespaces
// and installs the result wholesale via PolicyTable.Update. It runs only on the
// Run goroutine (plus tests calling it synchronously); the informer stores it
// reads are internally thread-safe.
func (w *PolicyWatcher) recompute() {
	podsByNS := make(map[string][]*corev1.Pod)
	known := make(map[netip.Addr]struct{})
	for _, obj := range w.pods.GetStore().List() {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			continue
		}
		if len(podIPsOf(pod)) == 0 {
			continue
		}
		podsByNS[pod.Namespace] = append(podsByNS[pod.Namespace], pod)
		for _, ip := range podIPsOf(pod) {
			known[ip] = struct{}{}
		}
	}
	nsLabels := make(map[string]labels.Set)
	for _, obj := range w.namespaces.GetStore().List() {
		ns, ok := obj.(*corev1.Namespace)
		if !ok {
			continue
		}
		nsLabels[ns.Name] = labels.Set(ns.Labels)
	}

	selected := make(map[netip.Addr][]PolicyRule)
	for _, obj := range w.policies.GetStore().List() {
		pol, ok := obj.(*networkingv1.NetworkPolicy)
		if !ok {
			continue
		}
		w.warnOncePerPolicy(pol)
		if !policyAppliesToIngress(pol) {
			// policyTypes: [Egress] only — the policy does not SELECT pods for ingress
			// purposes, so it must not manufacture an ingress deny. Egress rules are
			// not enforced at all (documented ceiling).
			continue
		}
		podSel, err := metav1.LabelSelectorAsSelector(&pol.Spec.PodSelector)
		if err != nil {
			// An unresolvable selection cannot safely deny anything: skipping the
			// policy entirely fails OPEN (fewer denies), per the hint contract.
			w.log.Warn("networkpolicy: podSelector does not parse; skipping policy (fail-open)",
				"networkpolicy", pol.Namespace+"/"+pol.Name, "err", err)
			continue
		}
		rules := make([]PolicyRule, 0, len(pol.Spec.Ingress))
		for i := range pol.Spec.Ingress {
			rules = append(rules, w.resolveRule(pol, &pol.Spec.Ingress[i], podsByNS, nsLabels))
		}
		for _, pod := range podsByNS[pol.Namespace] {
			if !podSel.Matches(labels.Set(pod.Labels)) {
				continue
			}
			for _, ip := range podIPsOf(pod) {
				// Assignment (not just append) so a zero-rule policy still creates the
				// map entry: a selected backend with NO allow rules is deny-all.
				selected[ip] = append(selected[ip], rules...)
			}
		}
	}
	w.table.Update(selected, known)
}

// resolveRule resolves one NetworkPolicyIngressRule to a concrete PolicyRule.
// Inexpressible clauses WIDEN, never narrow (dropping them would manufacture a
// deny upstream does not have): an ipBlock peer or an unparseable peer selector
// widens the rule to any-source (nil Sources); a named port, a port range
// (endPort), or a protocol-only entry widens the rule to any-port (nil Ports).
// The rule's protocol field is ignored entirely — a TCP-only allow also admits
// UDP on that port, again a widen-only divergence (documented in doc.go).
func (w *PolicyWatcher) resolveRule(pol *networkingv1.NetworkPolicy, rule *networkingv1.NetworkPolicyIngressRule, podsByNS map[string][]*corev1.Pod, nsLabels map[string]labels.Set) PolicyRule {
	var out PolicyRule

	if len(rule.From) > 0 {
		srcs := make(map[netip.Addr]struct{})
		wide := false
		for i := range rule.From {
			peer := &rule.From[i]
			if peer.IPBlock != nil {
				wide = true // ipBlock is out of the v0.2 subset: widen to any-source
				continue
			}
			nss, ok := w.peerNamespaces(pol, peer, nsLabels)
			if !ok {
				wide = true
				continue
			}
			var podSel labels.Selector = labels.Everything()
			if peer.PodSelector != nil {
				s, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
				if err != nil {
					w.log.Warn("networkpolicy: peer podSelector does not parse; widening rule to any source (fail-open)",
						"networkpolicy", pol.Namespace+"/"+pol.Name, "err", err)
					wide = true
					continue
				}
				podSel = s
			}
			for _, ns := range nss {
				for _, pod := range podsByNS[ns] {
					if !podSel.Matches(labels.Set(pod.Labels)) {
						continue
					}
					for _, ip := range podIPsOf(pod) {
						srcs[ip] = struct{}{}
					}
				}
			}
		}
		if !wide {
			out.Sources = srcs
		}
	}

	if len(rule.Ports) > 0 {
		ports := make(map[uint16]struct{}, len(rule.Ports))
		wide := false
		for i := range rule.Ports {
			p := &rule.Ports[i]
			switch {
			case p.Port == nil, p.Port.Type == intstr.String, p.EndPort != nil:
				// A protocol-only entry (nil Port), a NAMED port (intstr.String), or a
				// port RANGE (endPort) is out of the v0.2 subset: widen this rule to
				// any-port rather than mis-deny.
				wide = true
			default:
				v := p.Port.IntValue()
				if v >= 1 && v <= 65535 {
					ports[uint16(v)] = struct{}{}
				}
			}
		}
		if !wide {
			out.Ports = ports
		}
	}
	return out
}

// peerNamespaces returns the namespaces a peer's namespaceSelector resolves to
// (nil selector → the policy's own namespace, per upstream). ok=false means the
// selector did not parse, so the caller must widen (fail-open).
func (w *PolicyWatcher) peerNamespaces(pol *networkingv1.NetworkPolicy, peer *networkingv1.NetworkPolicyPeer, nsLabels map[string]labels.Set) ([]string, bool) {
	if peer.NamespaceSelector == nil {
		return []string{pol.Namespace}, true
	}
	sel, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
	if err != nil {
		w.log.Warn("networkpolicy: peer namespaceSelector does not parse; widening rule to any source (fail-open)",
			"networkpolicy", pol.Namespace+"/"+pol.Name, "err", err)
		return nil, false
	}
	var out []string
	for name, ls := range nsLabels {
		if sel.Matches(ls) {
			out = append(out, name)
		}
	}
	return out, true
}

// warnOncePerPolicy emits the honest-ceiling Warn once per policy (keyed ns/name,
// re-armed on delete): the subset enforces ONLY on Service-VIP-mediated ingress.
func (w *PolicyWatcher) warnOncePerPolicy(pol *networkingv1.NetworkPolicy) {
	key := pol.Namespace + "/" + pol.Name
	w.warnMu.Lock()
	already := w.warnedPolicies[key]
	if !already {
		w.warnedPolicies[key] = true
	}
	w.warnMu.Unlock()
	if already {
		return
	}
	w.log.Warn("NetworkPolicy enforced only on Service-VIP-mediated ingress; direct pod-IP traffic (incl. ALL headless/StatefulSet traffic) bypasses; egress/ipBlock not enforced",
		"networkpolicy", key)
}

// policyAppliesToIngress reports whether pol constrains ingress: an empty
// policyTypes defaults to Ingress (upstream API default), otherwise the list must
// name Ingress. An egress-only policy never selects pods for ingress purposes.
func policyAppliesToIngress(pol *networkingv1.NetworkPolicy) bool {
	if len(pol.Spec.PolicyTypes) == 0 {
		return true
	}
	for _, t := range pol.Spec.PolicyTypes {
		if t == networkingv1.PolicyTypeIngress {
			return true
		}
	}
	return false
}

// podIPsOf returns pod's parsed, Unmap'd IPs (Status.PodIPs, falling back to
// Status.PodIP). A pod with no assigned IP yet resolves to nothing — it cannot
// send or receive attributable traffic until it has one.
func podIPsOf(pod *corev1.Pod) []netip.Addr {
	var out []netip.Addr
	seen := make(map[netip.Addr]struct{}, len(pod.Status.PodIPs)+1)
	add := func(s string) {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return
		}
		a = a.Unmap()
		if _, dup := seen[a]; dup {
			return
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	for _, pip := range pod.Status.PodIPs {
		add(pip.IP)
	}
	if pod.Status.PodIP != "" {
		add(pod.Status.PodIP)
	}
	return out
}

// toNetworkPolicy extracts a NetworkPolicy from an informer object, unwrapping a
// DeletedFinalStateUnknown tombstone (mirrors toService/toSlice).
func toNetworkPolicy(obj any) (*networkingv1.NetworkPolicy, bool) {
	if pol, ok := obj.(*networkingv1.NetworkPolicy); ok {
		return pol, true
	}
	if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		if pol, ok := tomb.Obj.(*networkingv1.NetworkPolicy); ok {
			return pol, true
		}
	}
	return nil, false
}
