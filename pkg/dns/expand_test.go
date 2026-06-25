package dns

import (
	"reflect"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
)

// stdSearch is the standard Kubernetes pod search list for the default namespace.
func stdSearch() []string {
	return []string{"default.svc.cluster.local", "svc.cluster.local", "cluster.local"}
}

func stdConfig() netv1.DNSConfig {
	return netv1.DNSConfig{
		ClusterDNSIP:  "10.43.0.10",
		ClusterDomain: "cluster.local",
		SearchDomains: stdSearch(),
		// NDots zero => DefaultNDots (5) via WithDefaults.
	}
}

// TestCandidateNamesSearchExpansion maps to acceptance M1.2-a1's resolver core:
// it asserts the ndots/search expansion, with the load-bearing case that a SHORT
// name like "web" is expanded through the search list FIRST (the tell for a
// correct ndots loop — a skipped loop would query "web" as absolute and fail).
func TestCandidateNamesSearchExpansion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  netv1.DNSConfig
		in   string
		want []string
	}{
		{
			// 0 dots < ndots(5): search FIRST, then absolute. THE short-name tell.
			name: "short name web expands via search first",
			cfg:  stdConfig(),
			in:   "web",
			want: []string{
				"web.default.svc.cluster.local",
				"web.svc.cluster.local",
				"web.cluster.local",
				"web",
			},
		},
		{
			// 1 dot < ndots(5): cross-namespace short form, search first.
			name: "service.namespace expands via search first",
			cfg:  stdConfig(),
			in:   "web.default",
			want: []string{
				"web.default.default.svc.cluster.local",
				"web.default.svc.cluster.local",
				"web.default.cluster.local",
				"web.default",
			},
		},
		{
			// 4 dots < ndots(5): the fully-qualified cluster name, still < ndots,
			// so search is tried first but the absolute form is present too.
			name: "full svc name under ndots tries search then absolute",
			cfg:  stdConfig(),
			in:   "web.default.svc.cluster.local",
			want: []string{
				"web.default.svc.cluster.local.default.svc.cluster.local",
				"web.default.svc.cluster.local.svc.cluster.local",
				"web.default.svc.cluster.local.cluster.local",
				"web.default.svc.cluster.local",
			},
		},
		{
			name: "absolute name with trailing dot skips search",
			cfg:  stdConfig(),
			in:   "kubernetes.default.svc.cluster.local.",
			want: []string{"kubernetes.default.svc.cluster.local"},
		},
		{
			name: "external name with many dots tries absolute first",
			cfg: netv1.DNSConfig{
				ClusterDNSIP:  "10.43.0.10",
				ClusterDomain: "cluster.local",
				SearchDomains: stdSearch(),
				NDots:         2,
			},
			in: "a.b.example.com",
			want: []string{
				"a.b.example.com",
				"a.b.example.com.default.svc.cluster.local",
				"a.b.example.com.svc.cluster.local",
				"a.b.example.com.cluster.local",
			},
		},
		{
			name: "explicit ndots 1 makes a one-dot name absolute-first",
			cfg: netv1.DNSConfig{
				ClusterDNSIP:  "10.43.0.10",
				ClusterDomain: "cluster.local",
				SearchDomains: []string{"svc.cluster.local"},
				NDots:         1,
			},
			in: "foo.bar",
			want: []string{
				"foo.bar",
				"foo.bar.svc.cluster.local",
			},
		},
		{
			name: "no search domains yields the bare name only",
			cfg: netv1.DNSConfig{
				ClusterDNSIP:  "10.43.0.10",
				ClusterDomain: "cluster.local",
			},
			in:   "web",
			want: []string{"web"},
		},
		{
			name: "empty query yields nothing",
			cfg:  stdConfig(),
			in:   "   ",
			want: nil,
		},
		{
			name: "search domains with trailing dots are normalized",
			cfg: netv1.DNSConfig{
				ClusterDNSIP:  "10.43.0.10",
				ClusterDomain: "cluster.local",
				SearchDomains: []string{"svc.cluster.local.", "cluster.local."},
				NDots:         5,
			},
			in: "web",
			want: []string{
				"web.svc.cluster.local",
				"web.cluster.local",
				"web",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := candidateNames(tc.cfg, tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("candidateNames(%q):\n got: %v\nwant: %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestCandidateNamesShortNameAlwaysSearched is a focused guard on the regression
// that matters most: if the ndots loop is ever skipped, a short Service name
// stops resolving. It asserts the FIRST candidate for "web" is the search-
// expanded FQDN, never the bare name.
func TestCandidateNamesShortNameAlwaysSearched(t *testing.T) {
	t.Parallel()
	got := candidateNames(stdConfig(), "web")
	if len(got) == 0 {
		t.Fatal("no candidates for short name")
	}
	if got[0] == "web" {
		t.Fatalf("short name tried as absolute FIRST (ndots loop skipped): %v", got)
	}
	if got[0] != "web.default.svc.cluster.local" {
		t.Fatalf("first candidate = %q, want search-expanded web.default.svc.cluster.local", got[0])
	}
	// The bare name must still be present as a last resort.
	if got[len(got)-1] != "web" {
		t.Fatalf("bare name should be the last candidate, got %v", got)
	}
}

// TestResolverCandidates asserts the exported Candidates passes through to the
// pure expander with the resolver's defaulted config.
func TestResolverCandidates(t *testing.T) {
	t.Parallel()
	r, err := NewResolver(stdConfig())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	got := r.Candidates("web")
	want := []string{
		"web.default.svc.cluster.local",
		"web.svc.cluster.local",
		"web.cluster.local",
		"web",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Candidates(web) = %v, want %v", got, want)
	}
}
