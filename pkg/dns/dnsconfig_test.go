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
	"testing"

	netv1 "k3sm.io/apis/net/v1"
)

// TestPodDNSConfig asserts the per-pod DNSConfig carries the cluster VIP, the
// standard Kubernetes search list for the namespace, the default ndots, and
// validates and round-trips through the resolver expander to resolve a short
// Service name via search.
func TestPodDNSConfig(t *testing.T) {
	t.Parallel()
	cfg := PodDNSConfig("10.43.0.10", "cluster.local", "kube-system")

	if cfg.ClusterDNSIP != "10.43.0.10" || cfg.ClusterDomain != "cluster.local" {
		t.Fatalf("unexpected cluster fields: %+v", cfg)
	}
	wantSearch := []string{"kube-system.svc.cluster.local", "svc.cluster.local", "cluster.local"}
	if len(cfg.SearchDomains) != len(wantSearch) {
		t.Fatalf("search = %v, want %v", cfg.SearchDomains, wantSearch)
	}
	for i := range wantSearch {
		if cfg.SearchDomains[i] != wantSearch[i] {
			t.Fatalf("search[%d] = %q, want %q", i, cfg.SearchDomains[i], wantSearch[i])
		}
	}
	if cfg.NDots != netv1.DefaultNDots {
		t.Fatalf("ndots = %d, want %d", cfg.NDots, netv1.DefaultNDots)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("PodDNSConfig invalid: %v", err)
	}

	// A short Service name expands through this config's search list.
	cands := candidateNames(cfg, "metrics-server")
	if cands[0] != "metrics-server.kube-system.svc.cluster.local" {
		t.Fatalf("short name did not expand via pod search list: %v", cands)
	}
}

// TestDefaultClusterDomain pins the canonical cluster DNS domain default that
// single-sources the open-coded "cluster.local" literal (B42): the const value
// itself, plus the darwin-net defaulting path that must consume it —
// PodDNSConfig's empty-clusterDomain branch. It guards the const against
// drifting from the conventional value k3sm's --cluster-domain config supplies,
// and the defaulting path against silently diverging from it.
func TestDefaultClusterDomain(t *testing.T) {
	t.Parallel()

	t.Run("const pins the conventional cluster domain", func(t *testing.T) {
		t.Parallel()
		if DefaultClusterDomain != "cluster.local" {
			t.Fatalf("DefaultClusterDomain = %q, want %q", DefaultClusterDomain, "cluster.local")
		}
	})

	t.Run("PodDNSConfig defaults an empty clusterDomain to the const", func(t *testing.T) {
		t.Parallel()
		// Empty dnsVIP + empty clusterDomain exercises the defaulting branch.
		cfg := PodDNSConfig("", "", "ns1")
		if cfg.ClusterDomain != DefaultClusterDomain {
			t.Fatalf("ClusterDomain = %q, want %q", cfg.ClusterDomain, DefaultClusterDomain)
		}
		want := []string{"ns1.svc.cluster.local", "svc.cluster.local", "cluster.local"}
		if len(cfg.SearchDomains) != len(want) {
			t.Fatalf("search = %v, want %v", cfg.SearchDomains, want)
		}
		for i := range want {
			if cfg.SearchDomains[i] != want[i] {
				t.Fatalf("search[%d] = %q, want %q", i, cfg.SearchDomains[i], want[i])
			}
		}
	})
}
