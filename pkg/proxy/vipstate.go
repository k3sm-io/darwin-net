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
	"cmp"
	"net/netip"
	"slices"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	netv1 "k3sm.io/apis/net/v1"
)

// VIPState is one routing-table key as it stands: the Service port, the Service
// that owns it, its internalTrafficPolicy, and the Ready backends a connection to
// it may be routed to. Every field is a plain value, so the type marshals to JSON
// as is and can be compared across processes.
type VIPState struct {
	// ClusterIP is the VIP address.
	ClusterIP string `json:"clusterIP"`
	// Port is the Service port on ClusterIP.
	Port int32 `json:"port"`
	// Protocol is the L4 transport, "TCP" or "UDP".
	Protocol string `json:"protocol"`
	// Namespace and Name identify the owning Service. Both are empty for a key
	// installed without a Service name (a direct SetEndpointsPolicy caller).
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Policy is the internalTrafficPolicy applied to the port, "Cluster" or "Local".
	Policy string `json:"policy"`
	// Backends are the Ready backend addresses ("ip:port"), sorted by IP and then
	// port. It is empty, never nil, for a key with no Ready backend.
	Backends []string `json:"backends"`
	// LocalBackends is how many of Backends run on this node.
	LocalBackends int `json:"localBackends"`
	// Generation numbers the distinct backend sets installed for the key; it
	// changes only when the set, the node-local subset or the policy does.
	Generation uint64 `json:"generation"`
}

// Key returns the routing-table key the state describes.
func (s VIPState) Key() PortKey {
	return PortKey{ClusterIP: s.ClusterIP, Port: s.Port, Protocol: netv1.Protocol(s.Protocol)}
}

// VIPStates returns the state of every installed key, sorted by ClusterIP (as an
// address), then port, then protocol. It is the input of the node status row that
// compares what this proxy routes against the API's EndpointSlices: the caller
// builds a BackendSet view from each side and passes both to DiffBackendSets.
// A key whose backend set is empty is listed with no backends. The result is
// owned by the caller.
func (p *Proxy) VIPStates() []VIPState {
	return p.table.VIPStates()
}

// VIPStates is Proxy.VIPStates over the table itself.
func (t *RoutingTable) VIPStates() []VIPState {
	t.mu.Lock()
	defer t.mu.Unlock()
	states := t.load().states
	out := make([]VIPState, 0, len(t.meta))
	for key, m := range t.meta {
		v := VIPState{
			ClusterIP:  key.ClusterIP,
			Port:       key.Port,
			Protocol:   string(key.Protocol),
			Namespace:  m.namespace,
			Name:       m.name,
			Policy:     m.policy.String(),
			Backends:   []string{},
			Generation: m.gen,
		}
		if st := states[key]; st != nil {
			v.Backends = make([]string, len(st.all))
			for i, b := range st.all {
				v.Backends[i] = b.addr.String()
			}
			v.LocalBackends = len(st.locals)
		}
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b VIPState) int { return comparePortKey(a.Key(), b.Key()) })
	return out
}

// BackendSet is one key's Ready backend addresses ("ip:port"). DiffBackendSets
// treats it as a set: order and duplicates do not matter.
type BackendSet []string

// BackendSets returns the VIPStates as the have side of DiffBackendSets.
func BackendSets(states []VIPState) map[PortKey]BackendSet {
	out := make(map[PortKey]BackendSet, len(states))
	for _, s := range states {
		out[s.Key()] = BackendSet(s.Backends)
	}
	return out
}

// APIBackendSets derives, from Services and EndpointSlices as the API serves
// them, the Ready backend set this proxy installs for each served Service port.
// It is the same derivation the Watcher applies to its informer store: a Service
// is served per serviceToVIP (ClusterIP set, not headless or ExternalName, TCP or
// UDP ports), each port's endpoints come from the IPv4 slices labeled for the
// Service and matched by port name, and an endpoint is admitted by the routing
// table's own rule (Ready, valid, parseable IP; not-Ready and terminating ones
// are left out). Addresses render as netip.AddrPort.String, exactly as
// VIPStates renders them, so the two views compare equal through
// DiffBackendSets.
//
// static is the Watcher's fixed-backend override, keyed "namespace/name" (see
// WithStaticBackends); a Service named there takes those endpoints instead of
// its slices. Pass nil when there is none. Inputs are not modified.
func APIBackendSets(services []*corev1.Service, slices []*discoveryv1.EndpointSlice, static map[string][]netv1.Endpoint) map[PortKey]BackendSet {
	byService := make(map[string][]*discoveryv1.EndpointSlice)
	for _, sl := range slices {
		if sl == nil {
			continue
		}
		if name := sl.Labels[discoveryv1.LabelServiceName]; name != "" {
			key := sl.Namespace + "/" + name
			byService[key] = append(byService[key], sl)
		}
	}
	out := make(map[PortKey]BackendSet)
	for _, svc := range services {
		vip, _, _, ok, _ := serviceToVIP(svc)
		if !ok {
			continue
		}
		key := svc.Namespace + "/" + svc.Name
		for _, p := range vip.Ports {
			eps, pinned := static[key]
			if !pinned {
				eps = endpointsForPort(byService[key], p.Name)
			}
			set := BackendSet{}
			for _, ep := range eps {
				if ap, ok := admitEndpoint(ep); ok {
					set = append(set, ap.String())
				}
			}
			out[PortKey{ClusterIP: vip.ClusterIP, Port: p.Port, Protocol: defaultProto(p.Protocol)}] = BackendSet(normalizeSet(set))
		}
	}
	return out
}

// Divergence is one key whose backend set differs between two views.
type Divergence struct {
	// Key is the diverging Service port.
	Key PortKey
	// Want and Have are the two views' sets for Key, sorted and de-duplicated.
	// A key absent from one view has an empty set there.
	Want []string
	Have []string
	// Missing are the addresses in Want but not in Have; Extra are the reverse.
	Missing []string
	Extra   []string
}

// DiffBackendSets compares two views of the Ready backends per key and returns
// every key whose sets differ, sorted like VIPStates. A key absent from one view
// is the same as a key with an empty set there, so a Service with no Ready
// endpoint is not a divergence from a table with no entry for it.
//
// It is the one comparison between a source of truth (want: an API list) and a
// derived view (have: an informer store, or the routing table), shared by the
// Watcher's periodic check and the node status row, so the two never disagree on
// what counts as drift.
func DiffBackendSets(want, have map[PortKey]BackendSet) []Divergence {
	var out []Divergence
	visit := func(key PortKey) {
		w, h := normalizeSet(want[key]), normalizeSet(have[key])
		if slices.Equal(w, h) {
			return
		}
		out = append(out, Divergence{
			Key:     key,
			Want:    w,
			Have:    h,
			Missing: setMinus(w, h),
			Extra:   setMinus(h, w),
		})
	}
	for key := range want {
		visit(key)
	}
	for key := range have {
		if _, ok := want[key]; !ok {
			visit(key)
		}
	}
	slices.SortFunc(out, func(a, b Divergence) int { return comparePortKey(a.Key, b.Key) })
	return out
}

// normalizeSet returns a sorted, de-duplicated copy of s (never nil).
func normalizeSet(s BackendSet) []string {
	out := append([]string{}, s...)
	slices.Sort(out)
	return slices.Compact(out)
}

// setMinus returns the elements of a not in b; both are sorted and unique.
func setMinus(a, b []string) []string {
	var out []string
	for _, x := range a {
		if _, found := slices.BinarySearch(b, x); !found {
			out = append(out, x)
		}
	}
	return out
}

// comparePortKey orders keys by ClusterIP (numerically when both parse as
// addresses), then port, then protocol.
func comparePortKey(a, b PortKey) int {
	if a.ClusterIP != b.ClusterIP {
		aa, errA := netip.ParseAddr(a.ClusterIP)
		ba, errB := netip.ParseAddr(b.ClusterIP)
		if errA == nil && errB == nil {
			if c := aa.Compare(ba); c != 0 {
				return c
			}
		}
		return cmp.Compare(a.ClusterIP, b.ClusterIP)
	}
	if c := cmp.Compare(a.Port, b.Port); c != 0 {
		return c
	}
	return cmp.Compare(a.Protocol, b.Protocol)
}
