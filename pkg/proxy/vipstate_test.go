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
	"net/netip"
	"reflect"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netv1 "k3sm.io/apis/net/v1"
)

// TestVIPStates pins the per-key state listing: every installed key, the empty
// one included, sorted numerically by VIP, with the Service name, policy, sorted
// backends, local count and a generation that moves only when the set does.
func TestVIPStates(t *testing.T) {
	t.Parallel()
	tbl := NewRoutingTable(netip.MustParsePrefix("100.64.0.0/24"))
	a := PortKey{ClusterIP: "10.43.0.100", Port: 80, Protocol: netv1.ProtocolTCP}
	b := PortKey{ClusterIP: "10.43.0.9", Port: 53, Protocol: netv1.ProtocolUDP}
	tbl.installEndpoints(a, serviceRef{"default", "web"}, []netv1.Endpoint{
		{IP: "100.64.1.5", Port: 8080, Ready: true},
		{IP: "100.64.0.7", Port: 8080, Ready: true},
		{IP: "100.64.0.8", Port: 8080, Ready: false},
	}, trafficLocal, affinityConfig{})
	tbl.installEndpoints(b, serviceRef{"kube-system", "dns"}, nil, trafficCluster, affinityConfig{})

	got := tbl.VIPStates()
	want := []VIPState{
		{ClusterIP: "10.43.0.9", Port: 53, Protocol: "UDP", Namespace: "kube-system", Name: "dns", Policy: "Cluster", Backends: []string{}, Generation: 1},
		{ClusterIP: "10.43.0.100", Port: 80, Protocol: "TCP", Namespace: "default", Name: "web", Policy: "Local", Backends: []string{"100.64.0.7:8080", "100.64.1.5:8080"}, LocalBackends: 1, Generation: 1},
	}
	if len(got) != len(want) {
		t.Fatalf("VIPStates() = %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !vipStateEqual(got[i], want[i]) {
			t.Errorf("VIPStates()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	tbl.installEndpoints(a, serviceRef{"default", "web"}, []netv1.Endpoint{
		{IP: "100.64.0.7", Port: 8080, Ready: true},
		{IP: "100.64.1.5", Port: 8080, Ready: true},
	}, trafficLocal, affinityConfig{})
	if g := tbl.VIPStates()[1].Generation; g != 1 {
		t.Errorf("re-installing the same Ready set moved the generation to %d, want 1", g)
	}
	tbl.installEndpoints(a, serviceRef{"default", "web"}, nil, trafficLocal, affinityConfig{})
	if g := tbl.VIPStates()[1].Generation; g != 2 {
		t.Errorf("draining the set left the generation at %d, want 2", g)
	}
	tbl.Delete(b)
	if n := len(tbl.VIPStates()); n != 1 {
		t.Errorf("after Delete, VIPStates() has %d entries, want 1", n)
	}
}

func vipStateEqual(a, b VIPState) bool {
	if a.Backends == nil || !slices.Equal(a.Backends, b.Backends) {
		return false
	}
	a.Backends, b.Backends = nil, nil
	return reflect.DeepEqual(a, b)
}

// TestDiffBackendSets pins the one comparison the anti-entropy pass and the node
// status row share: absent equals empty, order and duplicates do not matter, and
// each divergence names the missing and extra addresses, sorted by key.
func TestDiffBackendSets(t *testing.T) {
	t.Parallel()
	k1 := PortKey{ClusterIP: "10.43.0.10", Port: 80, Protocol: netv1.ProtocolTCP}
	k2 := PortKey{ClusterIP: "10.43.0.9", Port: 80, Protocol: netv1.ProtocolTCP}
	tests := []struct {
		name string
		want map[PortKey]BackendSet
		have map[PortKey]BackendSet
		out  []Divergence
	}{
		{"both empty", nil, nil, nil},
		{"absent equals empty", map[PortKey]BackendSet{k1: {}}, nil, nil},
		{"order and duplicates ignored",
			map[PortKey]BackendSet{k1: {"a:1", "b:1"}},
			map[PortKey]BackendSet{k1: {"b:1", "a:1", "a:1"}}, nil},
		{"missing backend",
			map[PortKey]BackendSet{k1: {"a:1", "b:1"}},
			map[PortKey]BackendSet{k1: {"a:1"}},
			[]Divergence{{Key: k1, Want: []string{"a:1", "b:1"}, Have: []string{"a:1"}, Missing: []string{"b:1"}}}},
		{"extra backend on a key want lacks",
			nil,
			map[PortKey]BackendSet{k2: {"c:1"}},
			[]Divergence{{Key: k2, Want: []string{}, Have: []string{"c:1"}, Extra: []string{"c:1"}}}},
		{"sorted numerically by VIP",
			map[PortKey]BackendSet{k1: {"a:1"}, k2: {"a:1"}},
			nil,
			[]Divergence{
				{Key: k2, Want: []string{"a:1"}, Have: []string{}, Missing: []string{"a:1"}},
				{Key: k1, Want: []string{"a:1"}, Have: []string{}, Missing: []string{"a:1"}},
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DiffBackendSets(tt.want, tt.have)
			if len(got) != len(tt.out) {
				t.Fatalf("DiffBackendSets = %+v, want %+v", got, tt.out)
			}
			for i := range got {
				g, w := got[i], tt.out[i]
				if g.Key != w.Key || !strsEqual(g.Want, w.Want) || !strsEqual(g.Have, w.Have) ||
					!strsEqual(g.Missing, w.Missing) || !strsEqual(g.Extra, w.Extra) {
					t.Errorf("DiffBackendSets[%d] = %+v, want %+v", i, g, w)
				}
			}
		})
	}
}

func strsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestAPIBackendSets pins the shared derivation from API objects to Ready
// backend sets: only Ready endpoints are admitted (not-Ready, unknown-readiness
// and terminating ones are left out), slices of other Services and IPv6 slices
// are ignored, a static override replaces the slices, unserved Services yield
// no keys, and every address renders through netip exactly as the routing table
// stores it, so a non-canonical IPv6 literal compares equal to the table's view.
func TestAPIBackendSets(t *testing.T) {
	t.Parallel()
	tru, fls := true, false
	http := "http"
	p8080 := int32(8080)
	svc := func(ns, name, vip string) *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeClusterIP, ClusterIP: vip,
				Ports: []corev1.ServicePort{{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP}},
			},
		}
	}
	slice := func(name, svcName string, at discoveryv1.AddressType, eps ...discoveryv1.Endpoint) *discoveryv1.EndpointSlice {
		return &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default", Name: name,
				Labels: map[string]string{discoveryv1.LabelServiceName: svcName},
			},
			AddressType: at,
			Endpoints:   eps,
			Ports:       []discoveryv1.EndpointPort{{Name: &http, Port: &p8080}},
		}
	}
	ep := func(addr string, ready *bool, terminating bool) discoveryv1.Endpoint {
		return discoveryv1.Endpoint{
			Addresses: []string{addr},
			Conditions: discoveryv1.EndpointConditions{
				Ready: ready, Serving: &tru, Terminating: &terminating,
			},
		}
	}
	web := PortKey{ClusterIP: "10.43.0.80", Port: 80, Protocol: netv1.ProtocolTCP}
	api := PortKey{ClusterIP: "10.43.0.1", Port: 80, Protocol: netv1.ProtocolTCP}

	headless := svc("default", "headless", corev1.ClusterIPNone)
	services := []*corev1.Service{svc("default", "web", "10.43.0.80"), svc("default", "kubernetes", "10.43.0.1"), headless}
	sls := []*discoveryv1.EndpointSlice{
		slice("web-a", "web", discoveryv1.AddressTypeIPv4,
			ep("10.42.0.5", &tru, false),
			ep("10.42.0.6", &fls, false),
			ep("10.42.0.7", nil, false),
			ep("10.42.0.8", &fls, true),
		),
		slice("web-b", "web", discoveryv1.AddressTypeIPv4, ep("10.42.0.5", &tru, false), ep("10.42.1.9", &tru, false)),
		slice("web-v6", "web", discoveryv1.AddressTypeIPv6, ep("fd00::5", &tru, false)),
		slice("other", "other", discoveryv1.AddressTypeIPv4, ep("10.42.0.99", &tru, false)),
		slice("headless-a", "headless", discoveryv1.AddressTypeIPv4, ep("10.42.0.50", &tru, false)),
	}
	static := map[string][]netv1.Endpoint{
		"default/kubernetes": {{IP: "FD00:0:0::1", Port: 6444, Ready: true}},
	}

	got := APIBackendSets(services, sls, static)
	want := map[PortKey]BackendSet{
		web: {"10.42.0.5:8080", "10.42.1.9:8080"},
		api: {"[fd00::1]:6444"},
	}
	if len(got) != len(want) {
		t.Fatalf("APIBackendSets = %v, want %v", got, want)
	}
	for k, w := range want {
		if !slices.Equal(got[k], w) {
			t.Errorf("APIBackendSets[%s] = %v, want %v", k, got[k], w)
		}
	}

	// The table's own rendering of the same endpoints agrees, the non-canonical
	// IPv6 literal included.
	tbl := NewRoutingTable(netip.Prefix{})
	tbl.installEndpoints(web, serviceRef{"default", "web"}, endpointsForPort(sls[:2], "http"), trafficCluster, affinityConfig{})
	tbl.installEndpoints(api, serviceRef{"default", "kubernetes"}, static["default/kubernetes"], trafficCluster, affinityConfig{})
	if d := DiffBackendSets(got, BackendSets(tbl.VIPStates())); len(d) != 0 {
		t.Errorf("the table and APIBackendSets disagree: %+v", d)
	}
}
