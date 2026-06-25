package dns

import (
	"strings"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
)

// TestCorefile asserts the rendered CoreDNS configuration binds the VIP, is
// authoritative for the cluster domain, and forwards upstream.
func TestCorefile(t *testing.T) {
	t.Parallel()

	t.Run("binds VIP and serves cluster domain", func(t *testing.T) {
		t.Parallel()
		cf := CorefileOptions{
			ClusterDomain:     "cluster.local",
			BindIP:            "10.43.0.10",
			Port:              53,
			UpstreamResolvers: []string{"1.1.1.1", "8.8.8.8"},
		}.Corefile()

		for _, want := range []string{
			".:53 {",
			"bind 10.43.0.10",
			"kubernetes cluster.local in-addr.arpa ip6.arpa {",
			"pods insecure",
			"cache 30",
			"forward . 1.1.1.1 8.8.8.8",
			"errors",
		} {
			if !strings.Contains(cf, want) {
				t.Fatalf("Corefile missing %q:\n%s", want, cf)
			}
		}
	})

	t.Run("defaults port domain and upstream", func(t *testing.T) {
		t.Parallel()
		cf := CorefileOptions{}.Corefile()
		if !strings.Contains(cf, ".:53 {") {
			t.Fatalf("default port not 53:\n%s", cf)
		}
		if !strings.Contains(cf, "kubernetes cluster.local") {
			t.Fatalf("default domain not cluster.local:\n%s", cf)
		}
		if !strings.Contains(cf, "forward . /etc/resolv.conf") {
			t.Fatalf("default upstream not resolv.conf:\n%s", cf)
		}
		// No bind line when BindIP is empty.
		if strings.Contains(cf, "bind ") {
			t.Fatalf("unexpected bind line with empty BindIP:\n%s", cf)
		}
	})
}

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
