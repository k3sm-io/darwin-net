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
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"

	netv1 "k3sm.io/apis/net/v1"
)

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
// and drive byte-identical PickCluster (NodePort) fan-out sequences through the real
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

	// Drive both through the real routing table and assert PickCluster (NodePort path)
	// fan-out is byte-identical — the eTP read left backend selection untouched.
	eps := []netv1.Endpoint{
		{IP: "10.42.0.5", Port: 8080, Ready: true},
		{IP: "10.42.0.6", Port: 8080, Ready: true},
		{IP: "10.42.0.7", Port: 8080, Ready: true},
	}
	pick := func(vip netv1.ServiceVIP, pol trafficPolicy, aff affinityConfig) []netip.AddrPort {
		tbl := NewRoutingTable(netip.Prefix{})
		p := vip.Ports[0]
		key := PortKey{ClusterIP: vip.ClusterIP, Port: p.Port, Protocol: p.Protocol}
		tbl.SetEndpointsPolicy(key, eps, pol, aff)
		var seq []netip.AddrPort
		for i := 0; i < 7; i++ {
			b, err := tbl.PickCluster(key)
			if err != nil {
				t.Fatalf("PickCluster: %v", err)
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
