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
	"slices"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
)

// clusterBase is the standard ClusterFirst cluster DNSConfig a pod starts from:
// the three default search domains (<ns>.svc.<domain>, svc.<domain>, <domain>) and
// the cluster ndots. The merge augments these from a pod's spec.dnsConfig.
func clusterBase() netv1.DNSConfig {
	return netv1.DNSConfig{
		ClusterDNSIP:  "10.43.0.10",
		ClusterDomain: "cluster.local",
		SearchDomains: []string{"ns.svc.cluster.local", "svc.cluster.local", "cluster.local"},
		NDots:         netv1.DefaultNDots,
	}
}

func TestMergeDNSConfig(t *testing.T) {
	tests := []struct {
		name       string
		searches   []string
		ndots      int32
		wantSearch []string
		wantNDots  int32
	}{
		{
			// Under-cap append: a single pod search lands after the cluster ones.
			// ndots:0 is treated as unset, so the cluster default is kept (B20b).
			name:       "under-cap append, ndots:0 keeps cluster default",
			searches:   []string{"corp.internal"},
			ndots:      0,
			wantSearch: []string{"ns.svc.cluster.local", "svc.cluster.local", "cluster.local", "corp.internal"},
			wantNDots:  netv1.DefaultNDots,
		},
		{
			// A positive pod ndots overrides the cluster default.
			name:       "positive pod ndots overrides cluster default",
			searches:   []string{"corp.internal"},
			ndots:      2,
			wantSearch: []string{"ns.svc.cluster.local", "svc.cluster.local", "cluster.local", "corp.internal"},
			wantNDots:  2,
		},
		{
			// The CRITICAL boundary: over-cap + a duplicate. The pod adds six
			// searches, one of which (cluster.local) collides with a cluster entry.
			// Dedupe drops the collision (cluster wins), leaving cluster(3)+a,b,c,d,e
			// = exactly 8, so nothing is truncated and the order stays cluster-first.
			name:       "over-cap plus duplicate: dedupe drops cluster collision, cap at 8, cluster-first",
			searches:   []string{"a", "b", "cluster.local", "c", "d", "e"},
			ndots:      3,
			wantSearch: []string{"ns.svc.cluster.local", "svc.cluster.local", "cluster.local", "a", "b", "c", "d", "e"},
			wantNDots:  3,
		},
		{
			// Six UNIQUE pod searches (no collision): cluster(3)+6 = 9 > 8, so the
			// 6th unique pod search (f) is truncated. Proves the hard cap, not just
			// the dedupe path.
			name:       "over-cap no duplicate: sixth unique pod search is truncated at 8",
			searches:   []string{"a", "b", "c", "d", "e", "f"},
			ndots:      1,
			wantSearch: []string{"ns.svc.cluster.local", "svc.cluster.local", "cluster.local", "a", "b", "c", "d", "e"},
			wantNDots:  1,
		},
		{
			// A negative ndots is also treated as "no override": keep the cluster
			// default (only a strictly-positive pod ndots wins).
			name:       "negative ndots keeps cluster default",
			searches:   nil,
			ndots:      -1,
			wantSearch: []string{"ns.svc.cluster.local", "svc.cluster.local", "cluster.local"},
			wantNDots:  netv1.DefaultNDots,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := clusterBase()
			got := MergeDNSConfig(base, tt.searches, tt.ndots)

			if !slices.Equal(got.SearchDomains, tt.wantSearch) {
				t.Errorf("SearchDomains = %v, want %v", got.SearchDomains, tt.wantSearch)
			}
			// The cap is an invariant of every merge, not just the over-cap cases.
			if len(got.SearchDomains) > MaxSearchDomains {
				t.Errorf("SearchDomains length %d exceeds MaxSearchDomains %d", len(got.SearchDomains), MaxSearchDomains)
			}
			// Cluster-first: the cluster searches must remain the leading prefix —
			// a pod search can never preempt them.
			if !slices.Equal(got.SearchDomains[:len(base.SearchDomains)], base.SearchDomains) {
				t.Errorf("cluster searches not cluster-first: got prefix %v, want %v", got.SearchDomains[:len(base.SearchDomains)], base.SearchDomains)
			}
			if got.NDots != tt.wantNDots {
				t.Errorf("NDots = %d, want %d", got.NDots, tt.wantNDots)
			}
			// The cluster server VIP and domain are never overridden by the merge.
			if got.ClusterDNSIP != base.ClusterDNSIP {
				t.Errorf("ClusterDNSIP = %q, want %q (the merge must never touch the cluster server)", got.ClusterDNSIP, base.ClusterDNSIP)
			}
			if got.ClusterDomain != base.ClusterDomain {
				t.Errorf("ClusterDomain = %q, want %q (the merge must never touch the cluster domain)", got.ClusterDomain, base.ClusterDomain)
			}
		})
	}
}

// TestMergeDNSConfigDoesNotMutateBase proves the merge builds a fresh search slice
// and never mutates the caller's base — important because dedupe (reused from
// expand.go) compacts IN PLACE, so an accidental alias of base.SearchDomains would
// corrupt the caller's cluster config.
func TestMergeDNSConfigDoesNotMutateBase(t *testing.T) {
	base := clusterBase()
	orig := slices.Clone(base.SearchDomains)

	got := MergeDNSConfig(base, []string{"a", "b", "cluster.local", "c", "d", "e"}, 7)

	if !slices.Equal(base.SearchDomains, orig) {
		t.Fatalf("base.SearchDomains mutated by MergeDNSConfig: got %v, want %v", base.SearchDomains, orig)
	}
	// The returned slice must be an independent allocation: mutating it must not
	// reach back into base.
	if len(got.SearchDomains) > 0 {
		got.SearchDomains[0] = "tampered.example."
		if base.SearchDomains[0] == "tampered.example." {
			t.Fatal("MergeDNSConfig returned a slice aliasing base.SearchDomains")
		}
	}
}
