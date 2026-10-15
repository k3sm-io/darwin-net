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
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"

	netv1 "k3sm.io/apis/net/v1"
)

// breakerService builds a served Service named name on vip and its slice with n
// Ready backends.
func breakerService(name, vip string, n int) (*corev1.Service, *discoveryv1.EndpointSlice) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: vip,
			Ports: []corev1.ServicePort{{
				Name: "http", Port: 80, TargetPort: intstr.FromInt32(8080), Protocol: corev1.ProtocolTCP,
			}},
		},
	}
	ready := true
	port := int32(8080)
	pname := "http"
	sl := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default", Name: name + "-abc",
			Labels: map[string]string{discoveryv1.LabelServiceName: name},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{{Name: &pname, Port: &port}},
	}
	for i := range n {
		sl.Endpoints = append(sl.Endpoints, discoveryv1.Endpoint{
			Addresses:  []string{"10.42.0." + strconv.Itoa(10+i)},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		})
	}
	return svc, sl
}

// viewOf builds a serviceView of the named Services, each with its given number
// of Ready backends; a negative count leaves the Service out entirely.
func viewOf(counts map[string]int) serviceView {
	v := newServiceView()
	i := 0
	for name, n := range counts {
		i++
		if n < 0 {
			continue
		}
		svc, sl := breakerService(name, "10.43.1."+strconv.Itoa(i), n)
		v.addService(svc)
		v.addSlice(sl)
	}
	return v
}

// TestRepairBreaker pins the circuit breaker on anti-entropy repairs: a live list
// with no Services against a populated store, or one that would take backends
// away from more than half of the Services that have any, is withheld; additive
// or minority repairs go through.
func TestRepairBreaker(t *testing.T) {
	t.Parallel()
	w := NewWatcher(fake.NewSimpleClientset(), nil, slog.New(slog.DiscardHandler))
	tests := []struct {
		name  string
		store map[string]int
		live  map[string]int
		trip  bool
	}{
		{"empty live list against a populated store", map[string]int{"a": 1, "b": 2}, map[string]int{}, true},
		{"one of three loses a backend", map[string]int{"a": 2, "b": 2, "c": 2}, map[string]int{"a": 1, "b": 2, "c": 2}, false},
		{"two of three lose backends", map[string]int{"a": 2, "b": 2, "c": 2}, map[string]int{"a": 1, "b": 0, "c": 2}, true},
		{"two of four lose backends is not more than half", map[string]int{"a": 2, "b": 2, "c": 2, "d": 2}, map[string]int{"a": 1, "b": 1, "c": 2, "d": 2}, false},
		{"three Services vanish from the live list", map[string]int{"a": 1, "b": 1, "c": 1}, map[string]int{"a": -1, "b": -1, "c": 1}, true},
		{"additive repairs never trip", map[string]int{"a": 1, "b": 1}, map[string]int{"a": 3, "b": 2}, false},
		{"Services without backends do not count", map[string]int{"a": 0, "b": 0, "c": 2}, map[string]int{"a": 0, "b": 0, "c": 2}, false},
		{"empty store, empty live", map[string]int{}, map[string]int{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, live := viewOf(tt.store), viewOf(tt.live)
			// Same VIP per name on both sides: viewOf numbers in map order, so pin it.
			live = renumber(live, store)
			if got := w.breakerTripped(live, store, w.divergences(live, store)); got != tt.trip {
				t.Errorf("breakerTripped = %v, want %v", got, tt.trip)
			}
		})
	}
}

// renumber gives each live Service the ClusterIP its store namesake has, so the
// two views key the same ports.
func renumber(live, store serviceView) serviceView {
	for key, svc := range live.svcs {
		if s := store.svcs[key]; s != nil {
			svc.Spec.ClusterIP = s.Spec.ClusterIP
		}
	}
	return live
}

// fixedLister returns the same lists on every call.
type fixedLister struct {
	svcs           []corev1.Service
	slices         []discoveryv1.EndpointSlice
	svcRV, sliceRV string
}

func (l fixedLister) listServices(context.Context) ([]corev1.Service, string, error) {
	return l.svcs, l.svcRV, nil
}

func (l fixedLister) listEndpointSlices(context.Context) ([]discoveryv1.EndpointSlice, string, error) {
	return l.slices, l.sliceRV, nil
}

// seededWatcher builds a Watcher over newOrderProxy whose store holds svc and
// slices (not started) and whose table has been reconciled from it.
func seededWatcher(t *testing.T, client *fake.Clientset, lister liveLister, h *captureHandler, svc *corev1.Service, slices ...*discoveryv1.EndpointSlice) (*Watcher, *RoutingTable) {
	t.Helper()
	px, tbl := newOrderProxy(t)
	w := NewWatcher(client, px, slog.New(h), withLiveLister(lister), withConfirmDelay(0))
	if err := w.informers().svcs.GetStore().Add(svc); err != nil {
		t.Fatalf("seed service: %v", err)
	}
	for _, sl := range slices {
		if err := w.informers().slices.GetStore().Add(sl); err != nil {
			t.Fatalf("seed slice: %v", err)
		}
	}
	w.reconcileService(svc)
	return w, tbl
}

// assertBackendsStay asserts key keeps exactly want backends for the settle
// window, so a late reconcile cannot slip past the check.
func assertBackendsStay(t *testing.T, tbl *RoutingTable, key PortKey, want int, settle time.Duration) {
	t.Helper()
	deadline := time.Now().Add(settle)
	for time.Now().Before(deadline) {
		if n := tbl.Len(key); n != want {
			t.Fatalf("routing table for %s has %d backends, want %d", key, n, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestBreakerLeavesTheTable drives two full passes against a live list that
// lists no Services at all while the store and the API hold one: nothing is
// deleted, the breaker warns once for the episode, and the relist is requested.
func TestBreakerLeavesTheTable(t *testing.T) {
	t.Parallel()
	svc, sl := orderService(orderVIP, orderPort), orderSlice("10.42.0.5", 8080)
	key := PortKey{ClusterIP: orderVIP, Port: orderPort, Protocol: netv1.ProtocolTCP}
	h := &captureHandler{}
	client := fake.NewSimpleClientset(svc.DeepCopy(), sl.DeepCopy())
	w, tbl := seededWatcher(t, client, fixedLister{}, h, svc, sl)
	waitBackends(t, tbl, key, 1)

	for range 2 {
		if !w.antiEntropyPass(context.Background()) {
			t.Fatal("an empty live list against a populated store was not reported as a divergence")
		}
	}
	assertBackendsStay(t, tbl, key, 1, 200*time.Millisecond)
	var breaker, divergence int
	for _, r := range h.warns() {
		switch r.Message {
		case "anti-entropy repair withheld: the live list would remove backends from most Services at once; leaving the routing table as it is and relisting":
			breaker++
		case "service backend set in the informer store diverges from the API server; repairing from a live list":
			divergence++
		}
	}
	if breaker != 1 {
		t.Errorf("breaker Warns = %d over two passes, want 1", breaker)
	}
	if divergence != 1 {
		t.Errorf("divergence Warns = %d over two passes, want 1 (later passes are Debug)", divergence)
	}
	if n := w.relists.Load(); n != 1 {
		t.Errorf("relists = %d, want 1", n)
	}
}

// TestRepairKeepsANewerStoreObject pins the ordering guard: when the store
// already holds an object newer than the live list (a watch event delivered in
// the confirm gap), the repair is skipped and the table keeps the store's newer
// set; when the store's objects are older, the repair applies.
func TestRepairKeepsANewerStoreObject(t *testing.T) {
	t.Parallel()
	key := PortKey{ClusterIP: orderVIP, Port: orderPort, Protocol: netv1.ProtocolTCP}
	tests := []struct {
		name     string
		storeRV  string
		listRV   string
		wantKept bool
	}{
		{"store slice newer than the list: store wins", "12", "11", true},
		{"store slice older than the list: repair applies", "8", "11", false},
		{"unparseable versions: repair applies", "", "11", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc := orderService(orderVIP, orderPort)
			svc.ResourceVersion = "10"
			// The store's newer view: two Ready backends.
			stored := orderSlice("10.42.0.5", 8080)
			stored.Endpoints = append(stored.Endpoints, discoveryv1.Endpoint{
				Addresses:  []string{"10.42.0.6"},
				Conditions: stored.Endpoints[0].Conditions,
			})
			stored.ResourceVersion = tt.storeRV
			// The list's view: one Ready backend.
			listed := orderSlice("10.42.0.5", 8080)
			listed.ResourceVersion = "9"
			lister := fixedLister{
				svcs: []corev1.Service{*svc.DeepCopy()}, slices: []discoveryv1.EndpointSlice{*listed},
				svcRV: tt.listRV, sliceRV: tt.listRV,
			}
			w, tbl := seededWatcher(t, fake.NewSimpleClientset(), lister, &captureHandler{}, svc, stored)
			waitBackends(t, tbl, key, 2)

			live, err := w.listLive(context.Background())
			if err != nil {
				t.Fatalf("listLive: %v", err)
			}
			divs := w.divergences(live, storeView(w.informers()))
			if len(divs["default/web"]) == 0 {
				t.Fatal("the fixture does not diverge")
			}
			w.repairService("default/web", live, divs["default/web"])
			if tt.wantKept {
				assertBackendsStay(t, tbl, key, 2, 200*time.Millisecond)
				return
			}
			waitBackends(t, tbl, key, 1)
		})
	}
}
