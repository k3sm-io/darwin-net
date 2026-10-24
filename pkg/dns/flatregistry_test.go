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

package dns

import (
	"net/netip"
	"slices"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeServiceView is a mutable Service set standing in for the resolver's
// Service view, keyed "<namespace>/<name>".
type fakeServiceView struct {
	mu  sync.Mutex
	ips map[string]netip.Addr
}

func (v *fakeServiceView) set(ns, name string, ip netip.Addr) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.ips == nil {
		v.ips = map[string]netip.Addr{}
	}
	v.ips[ns+"/"+name] = ip
}

func (v *fakeServiceView) remove(ns, name string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.ips, ns+"/"+name)
}

func (v *fakeServiceView) lookup(ns, name string) (netip.Addr, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	ip, ok := v.ips[ns+"/"+name]
	return ip, ok
}

// podSearchForms returns the candidate names a pod in ns sends for the bare
// registry name, through the same ndots/search expansion the shim and the vm
// guest's resolv.conf apply, and checks it produced every expected form.
func podSearchForms(t *testing.T, ns string) []string {
	t.Helper()
	r, err := NewResolver(PodDNSConfig(DefaultDNSVIP, DefaultClusterDomain, ns))
	if err != nil {
		t.Fatalf("NewResolver(%s): %v", ns, err)
	}
	got := r.Candidates(RegistryServiceName)
	for _, want := range []string{
		"registry-k3sm." + ns + ".svc.cluster.local",
		"registry-k3sm.svc.cluster.local",
		"registry-k3sm.cluster.local",
	} {
		if !slices.ContainsFunc(got, func(c string) bool { return normalizeName(c) == want }) {
			t.Fatalf("candidates for a pod in %s = %v, missing %q", ns, got, want)
		}
	}
	return got
}

func TestFlatRegistryNameResolvesFromEveryNamespace(t *testing.T) {
	const domain = DefaultClusterDomain
	ipA := netip.MustParseAddr("10.43.12.34")
	ipB := netip.MustParseAddr("10.43.56.78")

	type query struct {
		name  string
		qtype dnsmessage.Type
	}
	a := func(names ...string) []query {
		qs := make([]query, len(names))
		for i, n := range names {
			qs[i] = query{n, dnsmessage.TypeA}
		}
		return qs
	}

	cases := []struct {
		name        string
		present     bool
		clusterIP   netip.Addr
		queries     []query
		wantHandled bool
		wantAddrs   []netip.Addr
	}{
		{
			name:    "bare name",
			present: true, clusterIP: ipA,
			queries:     a("registry-k3sm", "Registry-K3SM", "registry-k3sm."),
			wantHandled: true, wantAddrs: []netip.Addr{ipA},
		},
		{
			name:    "search forms from namespace default",
			present: true, clusterIP: ipA,
			queries:     a(podSearchForms(t, "default")...),
			wantHandled: true, wantAddrs: []netip.Addr{ipA},
		},
		{
			name:    "search forms from namespace team-a",
			present: true, clusterIP: ipA,
			queries:     a(podSearchForms(t, "team-a")...),
			wantHandled: true, wantAddrs: []netip.Addr{ipA},
		},
		{
			name:    "canonical FQDN stays an ordinary Service name",
			present: true, clusterIP: ipA,
			queries:     a("registry-k3sm.k3sm-registry.svc.cluster.local", "registry-k3sm.k3sm-registry.svc.cluster.local."),
			wantHandled: false,
		},
		{
			name:    "Service absent falls through to the normal path",
			present: false,
			queries: append(a("registry-k3sm", "registry-k3sm.svc.cluster.local", "registry-k3sm.cluster.local"),
				a(podSearchForms(t, "team-a")...)...),
			wantHandled: false,
		},
		{
			name:    "ClusterIP change is reflected",
			present: true, clusterIP: ipB,
			queries:     a("registry-k3sm", "registry-k3sm.default.svc.cluster.local"),
			wantHandled: true, wantAddrs: []netip.Addr{ipB},
		},
		{
			name:    "a name that only starts with the registry name is not rewritten",
			present: true, clusterIP: ipA,
			queries: a("registry-k3sm-x", "registry-k3sm-x.default.svc.cluster.local",
				"registry-k3sm-x.svc.cluster.local", "registry-k3sm-x.cluster.local",
				"registry-k3smx", "x.registry-k3sm", "registry-k3sm.default",
				"registry-k3sm.default.svc", "registry-k3sm.a.b.svc.cluster.local",
				"registry-k3sm.example.com"),
			wantHandled: false,
		},
		{
			name:    "AAAA is an empty NOERROR",
			present: true, clusterIP: ipA,
			queries: []query{
				{"registry-k3sm", dnsmessage.TypeAAAA},
				{"registry-k3sm.default.svc.cluster.local", dnsmessage.TypeAAAA},
				{"registry-k3sm.svc.cluster.local", dnsmessage.TypeAAAA},
			},
			wantHandled: true, wantAddrs: nil,
		},
	}

	// One view across the table, the way the resolver's Service view outlives
	// queries: the absent case deletes the entry the earlier cases read, and the
	// ClusterIP-change case recreates it with a different address.
	view := &fakeServiceView{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.present {
				view.set(RegistryServiceNamespace, RegistryServiceName, tc.clusterIP)
			} else {
				view.remove(RegistryServiceNamespace, RegistryServiceName)
			}
			// A Service named registry-k3sm elsewhere must not be what answers.
			view.set("default", RegistryServiceName, netip.MustParseAddr("10.43.99.99"))
			for _, q := range tc.queries {
				addrs, handled := ResolveFlatRegistryName(q.qtype, q.name, domain, view.lookup)
				if handled != tc.wantHandled {
					t.Fatalf("%s %s: handled = %v, want %v", q.qtype, q.name, handled, tc.wantHandled)
				}
				if !slices.Equal(addrs, tc.wantAddrs) {
					t.Fatalf("%s %s: addrs = %v, want %v", q.qtype, q.name, addrs, tc.wantAddrs)
				}
			}
		})
	}
}

func TestFlatRegistryNameDeclinesWithoutAView(t *testing.T) {
	view := &fakeServiceView{}
	view.set(RegistryServiceNamespace, RegistryServiceName, netip.MustParseAddr("10.43.1.1"))
	cases := []struct {
		name   string
		domain string
		lookup ServiceIPv4Lookup
	}{
		{"nil lookup", DefaultClusterDomain, nil},
		{"invalid cluster domain", "bad_domain", view.lookup},
		{"empty cluster domain", "", view.lookup},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, handled := ResolveFlatRegistryName(dnsmessage.TypeA, "registry-k3sm.svc.cluster.local", tc.domain, tc.lookup); handled {
				t.Fatal("handled = true, want false")
			}
		})
	}
	ipv6 := &fakeServiceView{}
	ipv6.set(RegistryServiceNamespace, RegistryServiceName, netip.MustParseAddr("fd00::1"))
	if _, handled := ResolveFlatRegistryName(dnsmessage.TypeA, "registry-k3sm", DefaultClusterDomain, ipv6.lookup); handled {
		t.Fatal("IPv6 ClusterIP: handled = true, want false")
	}
}
