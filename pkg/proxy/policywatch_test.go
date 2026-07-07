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
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

// testPod builds a running pod with labels and an assigned IP.
func testPod(ns, name, ip string, lbls map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: lbls},
		Status:     corev1.PodStatus{PodIP: ip, PodIPs: []corev1.PodIP{{IP: ip}}},
	}
}

// testNS builds a labeled namespace.
func testNS(name string, lbls map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: lbls}}
}

// newTestPolicyWatcher builds a PolicyWatcher over a fake clientset whose
// informer STORES are seeded directly (no informer goroutines), so tests call
// recompute() synchronously and assert the table verdicts — the pure-resolution
// analog of the watch_test.go handler-call idiom.
func newTestPolicyWatcher(t *testing.T, objs ...any) (*PolicyWatcher, *PolicyTable, *captureHandler) {
	t.Helper()
	h := &captureHandler{}
	pt := NewPolicyTable()
	w := NewPolicyWatcher(fake.NewSimpleClientset(), pt, slog.New(h))
	for _, obj := range objs {
		switch o := obj.(type) {
		case *corev1.Pod:
			if err := w.pods.GetStore().Add(o); err != nil {
				t.Fatalf("seed pod: %v", err)
			}
		case *corev1.Namespace:
			if err := w.namespaces.GetStore().Add(o); err != nil {
				t.Fatalf("seed namespace: %v", err)
			}
		case *networkingv1.NetworkPolicy:
			if err := w.policies.GetStore().Add(o); err != nil {
				t.Fatalf("seed networkpolicy: %v", err)
			}
		default:
			t.Fatalf("unsupported seed object %T", obj)
		}
	}
	return w, pt, h
}

// TestPolicyWatcherResolution proves the watcher's selector→/32 resolution: the
// debounced full recompute resolves podSelector/namespaceSelector from-clauses to
// concrete source sets, numeric ports to port sets, honors the upstream defaults
// (empty from = any source; zero rules = deny-all), skips egress-only policies,
// and WIDENS (never narrows) every inexpressible clause.
func TestPolicyWatcherResolution(t *testing.T) {
	t.Parallel()

	webIP := netip.MustParseAddr("10.42.0.20")
	cliProdIP := netip.MustParseAddr("10.42.0.21")
	cliDevIP := netip.MustParseAddr("10.42.0.22")
	base := []any{
		testNS("prod", map[string]string{"env": "prod"}),
		testNS("dev", map[string]string{"env": "dev"}),
		testPod("prod", "web", webIP.String(), map[string]string{"app": "web"}),
		testPod("prod", "cli-prod", cliProdIP.String(), map[string]string{"role": "cli"}),
		testPod("dev", "cli-dev", cliDevIP.String(), map[string]string{"role": "cli"}),
	}
	webPolicy := func(ingress ...networkingv1.NetworkPolicyIngressRule) *networkingv1.NetworkPolicy {
		return &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "web-policy"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				Ingress:     ingress,
			},
		}
	}
	port8080 := intstr.FromInt32(8080)

	t.Run("namespaceSelector+podSelector+ports resolve to concrete /32 and port sets", func(t *testing.T) {
		t.Parallel()
		pol := webPolicy(networkingv1.NetworkPolicyIngressRule{
			From: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "dev"}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"role": "cli"}},
			}},
			Ports: []networkingv1.NetworkPolicyPort{{Port: &port8080}},
		})
		w, pt, _ := newTestPolicyWatcher(t, append(base, any(pol))...)
		w.recompute()

		if !pt.Allow(cliDevIP, webIP, 8080) {
			t.Errorf("dev cli on the allowed port must pass")
		}
		if pt.Allow(cliProdIP, webIP, 8080) {
			t.Errorf("prod cli must be denied: the namespaceSelector matches dev only")
		}
		if pt.Allow(cliDevIP, webIP, 9090) {
			t.Errorf("allowed source on a NON-allowed port must be denied")
		}
		if !pt.Allow(cliDevIP, cliProdIP, 8080) {
			t.Errorf("an UNSELECTED backend must default-allow")
		}
	})

	t.Run("empty from allows any source; nil namespaceSelector scopes to the policy namespace", func(t *testing.T) {
		t.Parallel()
		pol := webPolicy(
			networkingv1.NetworkPolicyIngressRule{}, // no from, no ports: any source, any port
		)
		w, pt, _ := newTestPolicyWatcher(t, append(base, any(pol))...)
		w.recompute()
		if !pt.Allow(cliDevIP, webIP, 1234) || !pt.Allow(cliProdIP, webIP, 1) {
			t.Errorf("an empty from clause must admit any source on any port")
		}

		// Same-namespace scoping: a peer with ONLY a podSelector matches the
		// policy's own namespace, so the dev cli must be denied.
		pol2 := webPolicy(networkingv1.NetworkPolicyIngressRule{
			From: []networkingv1.NetworkPolicyPeer{{
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "cli"}},
			}},
		})
		w2, pt2, _ := newTestPolicyWatcher(t, append(base, any(pol2))...)
		w2.recompute()
		if !pt2.Allow(cliProdIP, webIP, 80) {
			t.Errorf("same-namespace cli must pass a namespace-scoped podSelector peer")
		}
		if pt2.Allow(cliDevIP, webIP, 80) {
			t.Errorf("other-namespace cli must be denied by a namespace-scoped podSelector peer")
		}
	})

	t.Run("zero ingress rules is deny-all for the selected backend", func(t *testing.T) {
		t.Parallel()
		w, pt, _ := newTestPolicyWatcher(t, append(base, any(webPolicy()))...)
		w.recompute()
		if pt.Allow(cliProdIP, webIP, 80) {
			t.Errorf("a selected backend with no ingress rules must deny attributable sources")
		}
		if !pt.Allow(cliProdIP, cliDevIP, 80) {
			t.Errorf("unselected backends stay default-allow")
		}
	})

	t.Run("egress-only policy never manufactures an ingress deny", func(t *testing.T) {
		t.Parallel()
		pol := webPolicy()
		pol.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
		w, pt, _ := newTestPolicyWatcher(t, append(base, any(pol))...)
		w.recompute()
		if !pt.Allow(cliProdIP, webIP, 80) {
			t.Errorf("policyTypes:[Egress] must not select the backend for ingress")
		}
	})

	t.Run("inexpressible clauses WIDEN: ipBlock peer -> any source, named port -> any port", func(t *testing.T) {
		t.Parallel()
		namedPort := intstr.FromString("http")
		pol := webPolicy(networkingv1.NetworkPolicyIngressRule{
			From: []networkingv1.NetworkPolicyPeer{
				{IPBlock: &networkingv1.IPBlock{CIDR: "192.0.2.0/24"}},
				{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "cli"}}},
			},
			Ports: []networkingv1.NetworkPolicyPort{{Port: &namedPort}},
		})
		w, pt, _ := newTestPolicyWatcher(t, append(base, any(pol))...)
		w.recompute()
		// The ipBlock peer widens the rule to ANY source, and the named port widens
		// it to ANY port: a source outside every selector still passes (widen-only —
		// the subset must never deny what upstream would allow).
		if !pt.Allow(cliDevIP, webIP, 9999) {
			t.Errorf("an ipBlock/named-port rule must widen, never narrow")
		}
	})

	t.Run("honest-ceiling warn fires once per policy and re-arms on delete", func(t *testing.T) {
		t.Parallel()
		pol := webPolicy()
		w, _, h := newTestPolicyWatcher(t, append(base, any(pol))...)
		w.recompute()
		w.recompute() // steady-state re-resolve: no re-warn
		ceiling := func() int {
			n := 0
			for _, r := range h.warns() {
				if strings.Contains(r.Message, "Service-VIP-mediated ingress") {
					n++
				}
			}
			return n
		}
		if got := ceiling(); got != 1 {
			t.Fatalf("honest-ceiling warn fired %d times across recomputes, want 1", got)
		}
		w.onPolicyDelete(pol) // delete re-arms
		w.recompute()
		if got := ceiling(); got != 2 {
			t.Fatalf("delete+recreate must re-warn: got %d, want 2", got)
		}
	})
}

// TestPolicyWatcherRunConverges exercises the production seam end-to-end: real
// informers over a fake clientset, WaitForCacheSync gating the first install
// (fail-open until then), and the debounced recompute converging the table after
// an API-driven policy change.
func TestPolicyWatcherRunConverges(t *testing.T) {
	t.Parallel()

	webIP := netip.MustParseAddr("10.42.0.20")
	cliIP := netip.MustParseAddr("10.42.0.21")
	client := fake.NewSimpleClientset(
		testNS("prod", map[string]string{"env": "prod"}),
		testPod("prod", "web", webIP.String(), map[string]string{"app": "web"}),
		testPod("prod", "cli", cliIP.String(), map[string]string{"role": "cli"}),
	)
	pt := NewPolicyTable()
	w := NewPolicyWatcher(client, pt, slog.New(&captureHandler{}))

	// Pre-Run (pre-sync): fail-open.
	if !pt.Allow(cliIP, webIP, 80) {
		t.Fatalf("pre-sync table must allow")
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- w.Run(ctx) }()

	pol := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "deny-all-web"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		},
	}
	if _, err := client.NetworkingV1().NetworkPolicies("prod").Create(context.Background(), pol, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create networkpolicy: %v", err)
	}

	deadline := time.Now().Add(policyTestTimeout)
	for pt.Allow(cliIP, webIP, 80) {
		if time.Now().After(deadline) {
			t.Fatalf("table did not converge to deny within %v of the policy create", policyTestTimeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The verdict converged; the unselected direction stays open.
	if !pt.Allow(webIP, cliIP, 80) {
		t.Fatalf("unselected backend must stay default-allow after convergence")
	}

	cancel()
	select {
	case err := <-runDone:
		if err != context.Canceled {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(policyTestTimeout):
		t.Fatalf("Run did not return after cancel")
	}
}
