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
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// countRecords counts captured records at level whose message contains substr
// and whose "resource" attribute is resource ("" matches any).
func countRecords(h *captureHandler, level slog.Level, substr, resource string) int {
	h.mu.Lock()
	recs := append([]slog.Record(nil), h.records...)
	h.mu.Unlock()
	n := 0
	for _, r := range recs {
		if r.Level != level || !strings.Contains(r.Message, substr) {
			continue
		}
		if resource != "" {
			if got, _ := attr(r, "resource"); got != resource {
				continue
			}
		}
		n++
	}
	return n
}

// runWatcher starts w.Run and returns a stop func that cancels it and waits for
// Run to return.
func runWatcher(t *testing.T, w *PolicyWatcher) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(policyTestTimeout):
			t.Fatalf("Run did not return after cancel")
		}
	}
}

// waitFor polls cond until it holds or policyTestTimeout passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(policyTestTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestPolicyWatcherPodNodeScopeSelectors pins which requests carry the node
// field selector: under WithPodNodeScope every pods list AND watch carries
// exactly spec.nodeName=<node>, while namespaces and networkpolicies stay
// unscoped; without the option (or with an empty node name) pods are unscoped.
func TestPolicyWatcherPodNodeScopeSelectors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		opts    []PolicyWatcherOption
		wantPod string
	}{
		{name: "node scope narrows pods only", opts: []PolicyWatcherOption{WithPodNodeScope("n1")}, wantPod: "spec.nodeName=n1"},
		{name: "default is cluster-wide", wantPod: ""},
		{name: "empty node name is cluster-wide", opts: []PolicyWatcherOption{WithPodNodeScope("")}, wantPod: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := fake.NewSimpleClientset()
			var mu sync.Mutex
			seen := map[string][]string{} // "verb resource" -> field selectors
			record := func(verb string, a k8stesting.Action, fs fields.Selector) {
				sel := ""
				if fs != nil {
					sel = fs.String()
				}
				mu.Lock()
				seen[verb+" "+a.GetResource().Resource] = append(seen[verb+" "+a.GetResource().Resource], sel)
				mu.Unlock()
			}
			client.PrependReactor("list", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
				if la, ok := a.(k8stesting.ListAction); ok {
					record("list", a, la.GetListRestrictions().Fields)
				}
				return false, nil, nil
			})
			client.PrependWatchReactor("*", func(a k8stesting.Action) (bool, watch.Interface, error) {
				if wa, ok := a.(k8stesting.WatchAction); ok {
					record("watch", a, wa.GetWatchRestrictions().Fields)
				}
				return false, nil, nil
			})

			w := NewPolicyWatcher(client, NewPolicyTable(), slog.New(&captureHandler{}), tc.opts...)
			stop := runWatcher(t, w)
			waitFor(t, "a list and a watch per resource", func() bool {
				mu.Lock()
				defer mu.Unlock()
				for _, r := range []string{"pods", "namespaces", "networkpolicies"} {
					if len(seen["list "+r]) == 0 || len(seen["watch "+r]) == 0 {
						return false
					}
				}
				return true
			})
			stop()

			mu.Lock()
			defer mu.Unlock()
			for key, sels := range seen {
				want := ""
				if strings.HasSuffix(key, " pods") {
					want = tc.wantPod
				}
				for _, got := range sels {
					if got != want {
						t.Errorf("%s carried field selector %q, want %q", key, got, want)
					}
				}
			}
		})
	}
}

// forbiddenPodsErr returns the Forbidden error a fake reactor produces for a
// pods list, the way a node identity's unscoped list is refused.
func forbiddenPodsErr(t *testing.T) error {
	t.Helper()
	client := fake.NewSimpleClientset()
	client.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("node may only list its own pods"))
	})
	_, err := client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if !apierrors.IsForbidden(err) {
		t.Fatalf("reactor returned %v, want a Forbidden error", err)
	}
	return err
}

// fakeClock is a settable time source for watchErrState.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// TestPolicyWatcherWatchErrorThrottle drives one informer's watch-error state
// with an injected clock: a persistent Forbidden produces one Warn per throttle
// window (not one per retry), recovery produces one Info and re-arms, and the
// benign watch-closed errors change nothing.
func TestPolicyWatcherWatchErrorThrottle(t *testing.T) {
	t.Parallel()
	forbidden := forbiddenPodsErr(t)
	const warnSub = "cannot list/watch"
	const infoSub = "informer recovered"

	newState := func(t *testing.T) (*watchErrState, *captureHandler, *fakeClock, *bool, *string) {
		t.Helper()
		h := &captureHandler{}
		w := NewPolicyWatcher(fake.NewSimpleClientset(), NewPolicyTable(), slog.New(h))
		st := w.watchErrs["pods"]
		clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
		synced, rv := false, ""
		st.now = clk.now
		st.synced = func() bool { return synced }
		st.rv = func() string { return rv }
		return st, h, clk, &synced, &rv
	}

	t.Run("persistent forbidden warns once per window, recovery informs once and re-arms", func(t *testing.T) {
		t.Parallel()
		st, h, clk, synced, _ := newState(t)
		ctx := context.Background()

		for i := 0; i < 6; i++ { // six retries spread over five minutes
			st.handle(ctx, nil, forbidden)
			clk.advance(time.Minute)
		}
		if got := countRecords(h, slog.LevelWarn, warnSub, "pods"); got != 1 {
			t.Fatalf("Warn lines within the throttle window = %d, want 1", got)
		}
		warns := h.warns()
		if f, _ := attr(warns[0], "forbidden"); f != "true" {
			t.Errorf("forbidden attr = %q, want true", f)
		}
		if !strings.Contains(warns[0].Message, "fail-open (allow-everything)") {
			t.Errorf("Warn must state the fail-open consequence: %q", warns[0].Message)
		}

		clk.advance(10 * time.Minute) // past the throttle
		st.handle(ctx, nil, forbidden)
		st.handle(ctx, nil, forbidden)
		if got := countRecords(h, slog.LevelWarn, warnSub, "pods"); got != 2 {
			t.Fatalf("Warn lines after the throttle elapsed = %d, want 2", got)
		}

		st.checkRecovered() // still not synced: no recovery
		if got := countRecords(h, slog.LevelInfo, infoSub, "pods"); got != 0 {
			t.Fatalf("recovery reported before the informer synced")
		}
		*synced = true
		st.checkRecovered()
		st.checkRecovered()
		if got := countRecords(h, slog.LevelInfo, infoSub, "pods"); got != 1 {
			t.Fatalf("Info recovery lines = %d, want 1", got)
		}

		st.handle(ctx, nil, forbidden) // re-armed: a new episode warns at once
		if got := countRecords(h, slog.LevelWarn, warnSub, "pods"); got != 3 {
			t.Fatalf("Warn lines after re-arm = %d, want 3", got)
		}
	})

	t.Run("failure after sync recovers only once the resource version moves", func(t *testing.T) {
		t.Parallel()
		st, h, _, synced, rv := newState(t)
		*synced, *rv = true, "100"
		st.handle(context.Background(), nil, forbidden)
		st.checkRecovered()
		if got := countRecords(h, slog.LevelInfo, infoSub, ""); got != 0 {
			t.Fatalf("recovery reported with no successful list or watch since the failure")
		}
		*rv = "101"
		st.checkRecovered()
		if got := countRecords(h, slog.LevelInfo, infoSub, "pods"); got != 1 {
			t.Fatalf("Info recovery lines = %d, want 1", got)
		}
	})

	t.Run("benign watch-closed errors are not failures", func(t *testing.T) {
		t.Parallel()
		st, h, _, _, _ := newState(t)
		for _, err := range []error{
			io.EOF,
			io.ErrUnexpectedEOF,
			apierrors.NewResourceExpired("too old resource version"),
			apierrors.NewGone("gone"),
		} {
			st.handle(context.Background(), nil, err)
		}
		if got := len(h.warns()); got != 0 {
			t.Fatalf("benign errors produced %d Warn lines, want 0", got)
		}
	})
}

// TestPolicyWatcherForbiddenWiring proves Run installs the handler on the real
// informer: a Forbidden pods list surfaces as the watcher's own Warn naming the
// resource, and the table stays fail-open.
func TestPolicyWatcherForbiddenWiring(t *testing.T) {
	t.Parallel()
	webIP := netip.MustParseAddr("10.42.0.20")
	cliIP := netip.MustParseAddr("10.42.0.21")
	client := fake.NewSimpleClientset()
	client.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("node may only list its own pods"))
	})
	h := &captureHandler{}
	pt := NewPolicyTable()
	w := NewPolicyWatcher(client, pt, slog.New(h))
	stop := runWatcher(t, w)
	defer stop()

	waitFor(t, "the pods watch-error Warn", func() bool {
		return countRecords(h, slog.LevelWarn, "cannot list/watch", "pods") > 0
	})
	for _, r := range h.warns() {
		if got, _ := attr(r, "resource"); got == "pods" {
			if f, _ := attr(r, "forbidden"); f != "true" {
				t.Errorf("forbidden attr = %q, want true", f)
			}
		}
	}
	if !pt.Allow(cliIP, webIP, 80) {
		t.Fatalf("an unsynced watcher must leave the table fail-open")
	}
}

// nodeScopedPodsClient seeds a clientset whose pods list honours the
// spec.nodeName field selector (the fake tracker ignores field selectors), so
// a node-scoped informer receives only that node's pods.
func nodeScopedPodsClient(t *testing.T, objs ...runtime.Object) *fake.Clientset {
	t.Helper()
	client := fake.NewSimpleClientset(objs...)
	podsGVR := corev1.SchemeGroupVersion.WithResource("pods")
	podsGVK := corev1.SchemeGroupVersion.WithKind("Pod")
	client.PrependReactor("list", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		la, ok := a.(k8stesting.ListAction)
		if !ok {
			return false, nil, nil
		}
		obj, err := client.Tracker().List(podsGVR, podsGVK, a.GetNamespace())
		if err != nil {
			return true, nil, err
		}
		all, ok := obj.(*corev1.PodList)
		if !ok {
			return true, nil, errors.New("tracker returned a non-PodList")
		}
		fs := la.GetListRestrictions().Fields
		out := &corev1.PodList{ListMeta: all.ListMeta}
		for _, p := range all.Items {
			if fs == nil || fs.Matches(fields.Set{"spec.nodeName": p.Spec.NodeName}) {
				out.Items = append(out.Items, p)
			}
		}
		return true, out, nil
	})
	return client
}

// TestPolicyWatcherNodeScopeVerdicts proves the node-scoped narrowing is
// widen-only at the local Service proxy: a policy on a local backend is
// enforced against a non-matching local client, a remote pod IP as a source is
// unknown and fails open, a policy selecting a remote-node pod produces no
// deny, and the mesh-egress seed always passes. The cluster-wide case over the
// same objects is the contrast: the two verdicts that differ move from deny to
// allow under node scope, never the other way.
func TestPolicyWatcherNodeScopeVerdicts(t *testing.T) {
	t.Parallel()

	webIP := netip.MustParseAddr("10.42.0.20")       // n1, selected by web-policy
	cliIP := netip.MustParseAddr("10.42.0.21")       // n1, allowed peer
	otherIP := netip.MustParseAddr("10.42.0.22")     // n1, not an allowed peer
	remoteOther := netip.MustParseAddr("10.42.1.22") // n2, not an allowed peer
	remoteDB := netip.MustParseAddr("10.42.1.30")    // n2, selected by db-deny-all
	meshEgress := netip.MustParseAddr("10.200.0.2")  // always-allow seed

	onNode := func(p *corev1.Pod, node string) *corev1.Pod { p.Spec.NodeName = node; return p }
	objs := func() []runtime.Object {
		return []runtime.Object{
			testNS("prod", map[string]string{"env": "prod"}),
			onNode(testPod("prod", "web", webIP.String(), map[string]string{"app": "web"}), "n1"),
			onNode(testPod("prod", "cli", cliIP.String(), map[string]string{"role": "cli"}), "n1"),
			onNode(testPod("prod", "other", otherIP.String(), map[string]string{"role": "other"}), "n1"),
			onNode(testPod("prod", "remote-other", remoteOther.String(), map[string]string{"role": "other"}), "n2"),
			onNode(testPod("prod", "db", remoteDB.String(), map[string]string{"app": "db"}), "n2"),
			&networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "web-policy"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						From: []networkingv1.NetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "cli"}},
						}},
					}},
				},
			},
			&networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "db-deny-all"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
				},
			},
		}
	}

	type verdict struct {
		name     string
		src, dst netip.Addr
		want     bool
	}
	cases := []struct {
		name     string
		opts     []PolicyWatcherOption
		verdicts []verdict
	}{
		{
			name: "node scope n1",
			opts: []PolicyWatcherOption{WithPodNodeScope("n1")},
			verdicts: []verdict{
				{"matching local client to local backend", cliIP, webIP, true},
				{"non-matching local client to local backend is denied", otherIP, webIP, false},
				{"remote pod source is unknown and fails open", remoteOther, webIP, true},
				{"policy on a remote backend produces no deny", cliIP, remoteDB, true},
				{"mesh-egress seed passes to a selected backend", meshEgress, webIP, true},
			},
		},
		{
			name: "cluster-wide contrast",
			verdicts: []verdict{
				{"matching local client to local backend", cliIP, webIP, true},
				{"non-matching local client to local backend is denied", otherIP, webIP, false},
				{"remote pod source is known and denied", remoteOther, webIP, false},
				{"policy on a remote backend denies", cliIP, remoteDB, false},
				{"mesh-egress seed passes to a selected backend", meshEgress, webIP, true},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := nodeScopedPodsClient(t, objs()...)
			pt := NewPolicyTable(meshEgress)
			w := NewPolicyWatcher(client, pt, slog.New(&captureHandler{}), tc.opts...)
			stop := runWatcher(t, w)
			defer stop()

			waitFor(t, "the first table install", func() bool { return !pt.Allow(otherIP, webIP, 80) })
			for _, v := range tc.verdicts {
				if got := pt.Allow(v.src, v.dst, 80); got != v.want {
					t.Errorf("%s: Allow(%s -> %s) = %v, want %v", v.name, v.src, v.dst, got, v.want)
				}
			}
		})
	}
}
