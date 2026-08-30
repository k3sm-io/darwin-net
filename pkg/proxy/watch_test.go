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
	"strconv"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	netv1 "k3sm.io/apis/net/v1"
)

// TestBackendsForPortStaticOverride pins the static-backend seam
// (WithStaticBackends): an overridden Service resolves to its pinned backend set
// — regardless of what EndpointSlices exist — while every other Service keeps the
// slice-derived path. The seam exists for the loopback-bound single-node
// apiserver: upstream EndpointSlice validation rejects loopback endpoint
// addresses on create, so no slice can carry 127.0.0.1:6444 and the kubernetes
// VIP would otherwise have no backend (in-pod client-go dials reset).
func TestBackendsForPortStaticOverride(t *testing.T) {
	static := map[string][]netv1.Endpoint{
		"default/kubernetes": {{IP: "127.0.0.1", Port: 6444, Ready: true}},
	}
	w := NewWatcher(fake.NewSimpleClientset(), nil, slog.New(slog.DiscardHandler), WithStaticBackends(static))

	ready := true
	https := "https"
	slicePort := int32(9999)
	slices := []*discoveryv1.EndpointSlice{{
		ObjectMeta:  metav1.ObjectMeta{Namespace: "default", Name: "stray"},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{"100.64.0.9"},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		}},
		Ports: []discoveryv1.EndpointPort{{Name: &https, Port: &slicePort}},
	}}

	tests := []struct {
		name     string
		key      string
		slices   []*discoveryv1.EndpointSlice
		wantN    int
		wantIP   string
		wantPort int32
	}{
		{"override wins even with slices present", "default/kubernetes", slices, 1, "127.0.0.1", 6444},
		{"override applies with no slices", "default/kubernetes", nil, 1, "127.0.0.1", 6444},
		{"non-overridden service keeps slice-derived backends", "default/web", slices, 1, "100.64.0.9", 9999},
		{"non-overridden service with no slices is empty", "default/web", nil, 0, "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eps := w.backendsForPort(tt.key, tt.slices, "https")
			if len(eps) != tt.wantN {
				t.Fatalf("backendsForPort(%s) returned %d endpoints, want %d", tt.key, len(eps), tt.wantN)
			}
			if tt.wantN == 0 {
				return
			}
			if eps[0].IP != tt.wantIP || eps[0].Port != tt.wantPort {
				t.Errorf("backendsForPort(%s) = %s:%d, want %s:%d", tt.key, eps[0].IP, eps[0].Port, tt.wantIP, tt.wantPort)
			}
			if !eps[0].Ready {
				t.Errorf("backendsForPort(%s) endpoint not Ready", tt.key)
			}
		})
	}
}

// captureHandler is a minimal slog.Handler that records emitted records so a test
// can assert on level, message, and attributes. Its mutex makes it -race-safe even
// though the Watcher touches it from a single goroutine here.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// warns returns the recorded WARN-level messages.
func (h *captureHandler) warns() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []slog.Record
	for _, r := range h.records {
		if r.Level == slog.LevelWarn {
			out = append(out, r)
		}
	}
	return out
}

// attr returns the value of key on r as a string, and whether it was present.
func attr(r slog.Record, key string) (string, bool) {
	var val string
	var found bool
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			val = a.Value.String()
			found = true
			return false
		}
		return true
	})
	return val, found
}

// eTPService builds a served ClusterIP Service with one TCP port; nodePort == 0
// means ClusterIP-only (no served NodePort) and etp == "" leaves the field unset.
func eTPService(etp corev1.ServiceExternalTrafficPolicy, nodePort int32) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"},
		Spec: corev1.ServiceSpec{
			Type:                  corev1.ServiceTypeClusterIP,
			ClusterIP:             "10.43.0.10",
			ExternalTrafficPolicy: etp,
			Ports: []corev1.ServicePort{{
				Name: "http", Port: 80, TargetPort: intstr.FromInt32(8080),
				Protocol: corev1.ProtocolTCP, NodePort: nodePort,
			}},
		},
	}
}

// newTestWatcher builds a Watcher whose Proxy treats the Service's ClusterIP as an
// exempt infra VIP, so reconcileService's ReconcilePolicy steps aside entirely (no
// worker goroutine, no listener) — the reconcile path stays inert and the test runs
// fully synchronous and -race-clean. The returned handler captures the Watcher's log.
func newTestWatcher(t *testing.T) (*Watcher, *captureHandler) {
	t.Helper()
	h := &captureHandler{}
	log := slog.New(h)
	px := New(NewRoutingTable(netip.Prefix{}), WithInfraVIPExemptions(netip.MustParseAddr("10.43.0.10")))
	w := NewWatcher(fake.NewSimpleClientset(), px, log)
	return w, h
}

// TestExternalTrafficPolicyLocalWarns proves the B56 datapath observability signal:
// externalTrafficPolicy:Local on a served NodePort emits exactly one throttled Warn
// per contiguous episode, from the single-goroutine onService path, WITHOUT
// perturbing routing (observability-only).
func TestExternalTrafficPolicyLocalWarns(t *testing.T) {
	t.Parallel()

	t.Run("Local+NodePort warns exactly once across redelivery and slice churn", func(t *testing.T) {
		t.Parallel()
		w, h := newTestWatcher(t)
		svc := eTPService(corev1.ServiceExternalTrafficPolicyLocal, 30080)

		// First delivery: warns.
		w.onService(svc)
		// Re-deliver the same Service (a Service informer update): throttled, no re-warn.
		w.onService(svc)
		// A reconcile driven by an EndpointSlice churn goes through reconcileService,
		// NOT onService — it must NEVER touch the throttle map or warn.
		w.reconcileService(svc)
		w.reconcileService(svc)

		warns := h.warns()
		if len(warns) != 1 {
			t.Fatalf("want exactly 1 warn across redelivery + slice churn, got %d", len(warns))
		}
		r := warns[0]
		if got, _ := attr(r, "service"); got != "default/web" {
			t.Errorf("service attr = %q, want default/web", got)
		}
		if got, _ := attr(r, "externalTrafficPolicy"); got != "Local" {
			t.Errorf("externalTrafficPolicy attr = %q, want Local", got)
		}
		if got, _ := attr(r, "delivered"); got != "Cluster" {
			t.Errorf("delivered attr = %q, want Cluster", got)
		}
		if got, ok := attr(r, "nodePorts"); !ok || got != "[30080]" {
			t.Errorf("nodePorts attr = %q (present=%v), want [30080]", got, ok)
		}
	})

	t.Run("Cluster does not warn", func(t *testing.T) {
		t.Parallel()
		w, h := newTestWatcher(t)
		w.onService(eTPService(corev1.ServiceExternalTrafficPolicyCluster, 30080))
		if n := len(h.warns()); n != 0 {
			t.Fatalf("eTP:Cluster warned %d times, want 0", n)
		}
	})

	t.Run("unset does not warn", func(t *testing.T) {
		t.Parallel()
		w, h := newTestWatcher(t)
		w.onService(eTPService("", 30080))
		if n := len(h.warns()); n != 0 {
			t.Fatalf("unset eTP warned %d times, want 0", n)
		}
	})

	t.Run("Local without a served NodePort does not warn", func(t *testing.T) {
		t.Parallel()
		w, h := newTestWatcher(t)
		// ClusterIP-only (NodePort 0): eTP:Local is a no-op on the ClusterIP path, so
		// the classifier gates on NodePort presence and stays silent. (A real
		// apiserver may reject eTP on a non-NodePort/LoadBalancer Service; the
		// darwin-net classifier is defensive and gates on NodePort regardless.)
		w.onService(eTPService(corev1.ServiceExternalTrafficPolicyLocal, 0))
		if n := len(h.warns()); n != 0 {
			t.Fatalf("eTP:Local without NodePort warned %d times, want 0", n)
		}
	})

	t.Run("Local to Cluster to Local re-arms the warn", func(t *testing.T) {
		t.Parallel()
		w, h := newTestWatcher(t)
		local := eTPService(corev1.ServiceExternalTrafficPolicyLocal, 30080)
		cluster := eTPService(corev1.ServiceExternalTrafficPolicyCluster, 30080)

		w.onService(local)   // warn (1)
		w.onService(cluster) // episode ends, warn cleared, no warn
		w.onService(local)   // re-armed → warn (2)
		if n := len(h.warns()); n != 2 {
			t.Fatalf("Local->Cluster->Local warned %d times, want 2 (re-armed)", n)
		}
	})

	t.Run("delete ends the episode and re-arms", func(t *testing.T) {
		t.Parallel()
		w, h := newTestWatcher(t)
		local := eTPService(corev1.ServiceExternalTrafficPolicyLocal, 30080)
		w.onService(local)       // warn (1)
		w.onServiceDelete(local) // clears the throttle entry
		w.onService(local)       // re-armed → warn (2)
		if n := len(h.warns()); n != 2 {
			t.Fatalf("delete+recreate warned %d times, want 2 (re-armed)", n)
		}
	})
}

// TestExternalTrafficPolicyReadIsObservabilityOnly proves the eTP read does NOT
// perturb backend selection: a Service that sets eTP:Local and an otherwise-identical
// control that leaves eTP unset translate to byte-identical (vip, policy, affinity),
// and drive byte-identical PickStickyCluster (NodePort) fan-out sequences through the real
// routing table. The eTP read changes ONLY the 5th classification return value.
func TestExternalTrafficPolicyReadIsObservabilityOnly(t *testing.T) {
	t.Parallel()

	localSvc := eTPService(corev1.ServiceExternalTrafficPolicyLocal, 30080)
	ctrlSvc := eTPService("", 30080)

	vipL, polL, affL, okL, unhonoredL := serviceToVIP(localSvc)
	vipC, polC, affC, okC, unhonoredC := serviceToVIP(ctrlSvc)

	if !okL || !okC {
		t.Fatalf("both services must be served (okL=%v okC=%v)", okL, okC)
	}
	// The ONLY difference the eTP read is allowed to make is the classification bit.
	if !unhonoredL {
		t.Errorf("eTP:Local+NodePort must classify as unhonored")
	}
	if unhonoredC {
		t.Errorf("unset eTP must NOT classify as unhonored")
	}
	// Routing-relevant outputs must be identical.
	if polL != polC {
		t.Errorf("trafficPolicy diverged: local=%d control=%d", polL, polC)
	}
	if affL != affC {
		t.Errorf("affinityConfig diverged: local=%+v control=%+v", affL, affC)
	}
	if len(vipL.Ports) != len(vipC.Ports) {
		t.Fatalf("port count diverged: local=%d control=%d", len(vipL.Ports), len(vipC.Ports))
	}
	for i := range vipL.Ports {
		if vipL.Ports[i] != vipC.Ports[i] {
			t.Fatalf("port[%d] diverged: local=%+v control=%+v", i, vipL.Ports[i], vipC.Ports[i])
		}
	}

	// Drive both through the real routing table and assert PickStickyCluster (the
	// NodePort path since B55) fan-out is byte-identical — the eTP read left backend
	// selection untouched.
	eps := []netv1.Endpoint{
		{IP: "10.42.0.5", Port: 8080, Ready: true},
		{IP: "10.42.0.6", Port: 8080, Ready: true},
		{IP: "10.42.0.7", Port: 8080, Ready: true},
	}
	client := netip.MustParseAddr("192.0.2.10")
	now := time.Unix(1000, 0)
	pick := func(vip netv1.ServiceVIP, pol trafficPolicy, aff affinityConfig) []netip.AddrPort {
		tbl := NewRoutingTable(netip.Prefix{})
		p := vip.Ports[0]
		key := PortKey{ClusterIP: vip.ClusterIP, Port: p.Port, Protocol: p.Protocol}
		tbl.SetEndpointsPolicy(key, eps, pol, aff)
		var seq []netip.AddrPort
		for i := 0; i < 7; i++ {
			b, err := tbl.PickStickyCluster(key, client, now)
			if err != nil {
				t.Fatalf("PickStickyCluster: %v", err)
			}
			seq = append(seq, b.Addr())
		}
		return seq
	}
	seqL := pick(vipL, polL, affL)
	seqC := pick(vipC, polC, affC)
	if len(seqL) != len(seqC) {
		t.Fatalf("pick sequence length diverged")
	}
	for i := range seqL {
		if seqL[i] != seqC[i] {
			t.Fatalf("pick[%d] diverged: local=%v control=%v — eTP read perturbed routing", i, seqL[i], seqC[i])
		}
	}
}

// orderService builds the served single-port ClusterIP Service the ordering
// reproduction drives. The VIP is a real bindable loopback address so the
// reconcile runs the production worker path end to end.
func orderService(clusterIP string, port int32) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: clusterIP,
			Ports: []corev1.ServicePort{{
				Name: "http", Port: port, TargetPort: intstr.FromInt32(8080),
				Protocol: corev1.ProtocolTCP,
			}},
		},
	}
}

// orderSlice builds the EndpointSlice for orderService's Service, labeled with
// kubernetes.io/service-name so onSlice maps it back.
func orderSlice(backendIP string, backendPort int32) *discoveryv1.EndpointSlice {
	ready := true
	name := "http"
	port := backendPort
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "web-abc",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "web"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{backendIP},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		}},
		Ports: []discoveryv1.EndpointPort{{Name: &name, Port: &port}},
	}
}

// newOrderProxy builds a rootless Proxy (noop alias manager) plus its routing
// table and starts its supervision loop, tearing it down at test end. The routing
// table is the observation seam: runWorker calls SetEndpointsPolicy from the event
// payload BEFORE it touches any listener, so a backend appearing there proves a
// reconcile carried it — the listener-open retry cannot fabricate one.
func newOrderProxy(t *testing.T) (*Proxy, *RoutingTable) {
	t.Helper()
	tbl := NewRoutingTable(netip.Prefix{})
	px := New(tbl, withAliasManager(newNoopAliasManager()), WithLogger(slog.New(slog.DiscardHandler)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = px.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return px, tbl
}

// assertNoBackends asserts key carries NO backends for the whole settle window,
// so it cannot pass on a reconcile that simply has not arrived yet. It is the
// negative counterpart of waitBackends.
func assertNoBackends(t *testing.T, tbl *RoutingTable, key PortKey, settle time.Duration) {
	t.Helper()
	deadline := time.Now().Add(settle)
	for time.Now().Before(deadline) {
		if n := tbl.Len(key); n != 0 {
			t.Fatalf("routing table for %s has %d backends, want 0", key, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestSliceBeforeServiceIsNotLost is the B160 gate. onSlice silently returns when
// the slice's Service is not yet in the Service informer's store, and both
// informers run with resyncPeriod 0, so that event is never re-delivered. The
// question is whether the DROP is LOSSY — whether a Service whose slice was
// observed first is left with no (or stale) backends forever.
//
// IT IS NOT, and this test is the standing proof. The drop is real (pinned by the
// "onSlice drops" case and by the empty-table assertion before the Service is
// created), but it costs a redundant reconcile, never a backend: reconcileService
// recomputes the WHOLE backend set from the EndpointSlice store on every event, and
// a shared informer adds an object to its store BEFORE dispatching that object's
// event (sharedIndexInformer.HandleDeltas). So a slice already in the slice store
// when its Service arrives is necessarily visible to that Service's own Add
// handler. Formally: slice-store-add -> (svc-store read that saw nothing) ->
// svc-store-add -> slice-store read, so the last read always sees the slice. A
// re-queue-on-miss or a non-zero resyncPeriod would buy nothing here.
//
// The gate is not vacuous: with onService reconciling from an empty slice set (the
// world the "lost" hypothesis describes), the three ordering cases below go red
// while "Service then slice" stays green — it discriminates ORDERING.
//
// It exercises ordering ONLY. Its observation seam is the routing table, which
// runWorker fills from the event payload BEFORE it touches any listener, so the
// listener-open retry cannot make it pass.
func TestSliceBeforeServiceIsNotLost(t *testing.T) {
	t.Parallel()

	t.Run("real informers: slice observed before its Service still lands in the routing table", func(t *testing.T) {
		t.Parallel()
		const vip = "127.0.0.1"
		port := freePort(t, vip)
		key := PortKey{ClusterIP: vip, Port: port, Protocol: netv1.ProtocolTCP}

		// The slice pre-exists, so it arrives in the EndpointSlice informer's initial
		// LIST; the Service is created only afterwards. That is the slice-then-Service
		// ordering, forced rather than raced.
		client := fake.NewSimpleClientset(orderSlice("10.42.0.5", 8080))
		px, tbl := newOrderProxy(t)
		w := NewWatcher(client, px, slog.New(slog.DiscardHandler))

		ctx, cancel := context.WithCancel(context.Background())
		runDone := make(chan struct{})
		go func() { defer close(runDone); _ = w.Run(ctx) }()
		// Cancel BEFORE joining: Run blocks on ctx.Done, so the join must follow the
		// cancel (a defer pair in the other order deadlocks).
		defer func() {
			cancel()
			<-runDone
		}()

		if !cache.WaitForCacheSync(ctx.Done(), w.svcs.HasSynced, w.slices.HasSynced) {
			t.Fatal("informer cache sync failed")
		}
		// The drop itself: the slice is cached but no reconcile has carried it,
		// because its Service was not in the Service store when onSlice ran.
		assertNoBackends(t, tbl, key, 200*time.Millisecond)
		if n := len(w.slicesForService("default", "web")); n != 1 {
			t.Fatalf("slice informer cached %d slices for default/web, want 1", n)
		}

		// The Service arrives second. Nothing re-delivers the dropped slice event —
		// so if the drop were lossy, the table would stay empty.
		if _, err := client.CoreV1().Services("default").Create(ctx, orderService(vip, port), metav1.CreateOptions{}); err != nil {
			t.Fatalf("create service: %v", err)
		}
		waitBackends(t, tbl, key, 1)
		got := tbl.Backends(key)
		if addr := got[0].Addr().String(); addr != "10.42.0.5:8080" {
			t.Errorf("backend = %s, want 10.42.0.5:8080", addr)
		}
	})

	t.Run("handler seam: both orderings converge on the same backend set", func(t *testing.T) {
		t.Parallel()
		// Drives the two handlers directly in each order, mirroring the informer
		// contract that a shared informer adds an object to its store BEFORE it
		// dispatches that object's event (sharedIndexInformer.HandleDeltas).
		tests := []struct {
			name        string
			sliceFirst  bool
			wantBackend string
		}{
			{"Service then slice", false, "10.42.0.5:8080"},
			{"slice then Service", true, "10.42.0.5:8080"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				const vip = "127.0.0.1"
				port := freePort(t, vip)
				key := PortKey{ClusterIP: vip, Port: port, Protocol: netv1.ProtocolTCP}

				px, tbl := newOrderProxy(t)
				w := NewWatcher(fake.NewSimpleClientset(), px, slog.New(slog.DiscardHandler))
				svc := orderService(vip, port)
				sl := orderSlice("10.42.0.5", 8080)

				deliverSvc := func() {
					if err := w.svcs.GetStore().Add(svc); err != nil {
						t.Fatalf("seed service store: %v", err)
					}
					w.onService(svc)
				}
				deliverSlice := func() {
					if err := w.slices.GetStore().Add(sl); err != nil {
						t.Fatalf("seed slice store: %v", err)
					}
					w.onSlice(sl)
				}
				if tt.sliceFirst {
					deliverSlice()
					deliverSvc()
				} else {
					deliverSvc()
					deliverSlice()
				}

				waitBackends(t, tbl, key, 1)
				got := tbl.Backends(key)
				if addr := got[0].Addr().String(); addr != tt.wantBackend {
					t.Errorf("%s: backend = %s, want %s", tt.name, addr, tt.wantBackend)
				}
			})
		}
	})

	t.Run("concurrent creation converges regardless of which informer wins", func(t *testing.T) {
		t.Parallel()
		// The adversarial ordering: both objects are created AFTER cache sync, from
		// two goroutines, so the Service and EndpointSlice informers race to deliver
		// them. Every interleaving — Service first, slice first, or simultaneous —
		// must converge on the backend. Repeated so a narrow window would surface.
		for i := 0; i < 20; i++ {
			const vip = "127.0.0.1"
			port := freePort(t, vip)
			key := PortKey{ClusterIP: vip, Port: port, Protocol: netv1.ProtocolTCP}

			client := fake.NewSimpleClientset()
			px, tbl := newOrderProxy(t)
			w := NewWatcher(client, px, slog.New(slog.DiscardHandler))

			ctx, cancel := context.WithCancel(context.Background())
			runDone := make(chan struct{})
			go func() { defer close(runDone); _ = w.Run(ctx) }()
			if !cache.WaitForCacheSync(ctx.Done(), w.svcs.HasSynced, w.slices.HasSynced) {
				cancel()
				<-runDone
				t.Fatal("informer cache sync failed")
			}

			var wg sync.WaitGroup
			wg.Add(2)
			var svcErr, sliceErr error
			go func() {
				defer wg.Done()
				_, svcErr = client.CoreV1().Services("default").Create(ctx, orderService(vip, port), metav1.CreateOptions{})
			}()
			go func() {
				defer wg.Done()
				_, sliceErr = client.DiscoveryV1().EndpointSlices("default").Create(ctx, orderSlice("10.42.0.5", 8080), metav1.CreateOptions{})
			}()
			wg.Wait()
			if svcErr != nil || sliceErr != nil {
				cancel()
				<-runDone
				t.Fatalf("iteration %d: create service=%v slice=%v", i, svcErr, sliceErr)
			}

			waitBackends(t, tbl, key, 1)
			// Re-read rather than index blind: Len and Backends are two separate lock
			// acquisitions, so a regression that lets a stale empty reconcile land
			// between them must report itself, not panic with an index-out-of-range
			// that buries the diagnosis (B207).
			got := tbl.Backends(key)
			if len(got) != 1 {
				t.Fatalf("iteration %d: backends = %d, want 1 (a stale reconcile overtook a fresh one)", i, len(got))
			}
			if addr := got[0].Addr().String(); addr != "10.42.0.5:8080" {
				t.Fatalf("iteration %d: backend = %s, want 10.42.0.5:8080", i, addr)
			}
			cancel()
			<-runDone
		}
	})

	t.Run("onSlice drops an event whose Service is uncached", func(t *testing.T) {
		t.Parallel()
		// Pins the MECHANISM the two cases above are about: with the slice cached but
		// its Service absent, onSlice reconciles nothing at all.
		const vip = "127.0.0.1"
		port := freePort(t, vip)
		key := PortKey{ClusterIP: vip, Port: port, Protocol: netv1.ProtocolTCP}

		px, tbl := newOrderProxy(t)
		w := NewWatcher(fake.NewSimpleClientset(), px, slog.New(slog.DiscardHandler))
		sl := orderSlice("10.42.0.5", 8080)
		if err := w.slices.GetStore().Add(sl); err != nil {
			t.Fatalf("seed slice store: %v", err)
		}
		w.onSlice(sl)
		assertNoBackends(t, tbl, key, 200*time.Millisecond)
	})
}

// TestReconcileSnapshotIsNotOvertaken pins the B207 mechanism: reconcileService
// reads the EndpointSlice cache and THEN delivers the resulting backend set to the
// per-VIP worker, and those two steps run on two different informer goroutines. If
// they are not serialized per Service, a goroutine descheduled between them lands
// an older snapshot on top of a newer one and the Service blackholes — the
// informers run a 0 resync period, so nothing ever recomputes it.
//
// The test drives exactly that interleaving: one goroutine reconciles against a
// slice cache that does NOT yet hold the Service's slice (so it snapshots an empty
// backend set), while a second adds the slice and reconciles (snapshotting the real
// backend). Whatever order they finish in, the table MUST end holding the backend,
// because the second snapshot is strictly newer.
//
// The cache is padded with unrelated slices so slicesForService — an O(cache) list
// and filter — takes long enough for the loser to be overtaken. That widens the
// window; it does not create it.
func TestReconcileSnapshotIsNotOvertaken(t *testing.T) {
	t.Parallel()
	const (
		vip        = "127.0.0.1"
		iterations = 50
		padding    = 400
	)

	for i := 0; i < iterations; i++ {
		port := freePort(t, vip)
		key := PortKey{ClusterIP: vip, Port: port, Protocol: netv1.ProtocolTCP}

		px, tbl := newOrderProxy(t)
		w := NewWatcher(fake.NewSimpleClientset(), px, slog.New(slog.DiscardHandler))

		svc := orderService(vip, port)
		if err := w.svcs.GetStore().Add(svc); err != nil {
			t.Fatalf("iteration %d: seed service store: %v", i, err)
		}
		// Unrelated slices: they widen the snapshot, and slicesForService must filter
		// every one of them out (they carry a different service-name label).
		for j := 0; j < padding; j++ {
			pad := orderSlice("10.42.9.9", 8080)
			pad.Name = "noise-" + strconv.Itoa(j)
			pad.Labels[discoveryv1.LabelServiceName] = "other"
			if err := w.slices.GetStore().Add(pad); err != nil {
				t.Fatalf("iteration %d: seed padding: %v", i, err)
			}
		}

		// The stale reconciler: it starts while the Service's own slice is absent, so
		// its snapshot is empty.
		entered := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			close(entered)
			w.reconcileService(svc)
		}()

		// The fresh reconciler: the slice exists before it snapshots, so its snapshot
		// carries the backend.
		<-entered
		if err := w.slices.GetStore().Add(orderSlice("10.42.0.5", 8080)); err != nil {
			t.Fatalf("iteration %d: seed slice store: %v", i, err)
		}
		w.reconcileService(svc)
		wg.Wait()

		waitBackends(t, tbl, key, 1)
		got := tbl.Backends(key)
		if len(got) != 1 || got[0].Addr().String() != "10.42.0.5:8080" {
			t.Fatalf("iteration %d: backends = %v, want [10.42.0.5:8080] (a stale snapshot overtook a fresh one)", i, got)
		}
	}
}
