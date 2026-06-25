package dns

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// podResolver builds a Resolver for a pod in namespace ns whose CoreDNS queries
// are redirected to the in-process stub (regardless of the configured VIP). It
// uses the production PodDNSConfig so the search list and ndots are exactly what
// a real pod receives.
func podResolver(t *testing.T, ns string, stub *stubDNS) *Resolver {
	t.Helper()
	cfg := PodDNSConfig("10.43.0.10", "cluster.local", ns)
	r, err := NewResolver(cfg, dialToStub(stub), WithTimeout(time.Second))
	if err != nil {
		t.Fatalf("NewResolver(ns=%s): %v", ns, err)
	}
	return r
}

// TestInPodKubernetesAndCrossNamespaceResolution maps to acceptance M2.2-a1: it
// proves the in-pod-API name kubernetes.default.svc (and its FQDN form) resolve
// through the resolver's candidate-name expansion to the apiserver-auto-created
// kubernetes ClusterIP, that a cross-namespace <svc>.<ns> form resolves to the
// RIGHT service FQDN, and that a BARE name does NOT cross namespaces (the
// Kubernetes DNS contract). CoreDNS (the stub) knows only the canonical cluster
// FQDNs, so a resolver that skipped search expansion — or one that wrongly
// searched every namespace — would fail these cases.
//
// This is the darwin-net half of M2.2: the resolution logic itself. The full
// in-pod path additionally requires runtimed's NON-platform exec-shim backend,
// because Apple's sandbox-exec strips DYLD_* (so the getaddrinfo shim only loads
// there) — see doc.go and docs/PHASES.md M2.2 for that documented constraint.
func TestInPodKubernetesAndCrossNamespaceResolution(t *testing.T) {
	t.Parallel()

	// kubeAddr is the apiserver-auto-created kubernetes ClusterIP; dbAddr is a
	// service named "db" living in namespace "prod".
	kubeAddr := netip.MustParseAddr("10.43.0.1")
	dbAddr := netip.MustParseAddr("10.43.0.50")

	cases := []struct {
		name string
		// podNS is the namespace the querying pod runs in (drives its search list).
		podNS string
		// zone is what CoreDNS knows: canonical <svc>.<ns>.svc.<domain> FQDNs only.
		zone map[string]netip.Addr
		// query is the name the in-pod client looks up.
		query string
		// want is the address it must resolve to (ignored when wantNotFound).
		want netip.Addr
		// wantNotFound asserts the lookup fails with ErrNotFound.
		wantNotFound bool
		// askedFQDN, when set, is the canonical FQDN the resolver MUST have queried,
		// proving the candidate that resolved was the right one.
		askedFQDN string
		// notAskedFQDN, when set, is an FQDN the resolver must NEVER have queried.
		notAskedFQDN string
	}{
		{
			name:      "kubernetes.default.svc.cluster.local FQDN resolves to the kubernetes ClusterIP",
			podNS:     "default",
			zone:      map[string]netip.Addr{"kubernetes.default.svc.cluster.local": kubeAddr},
			query:     "kubernetes.default.svc.cluster.local",
			want:      kubeAddr,
			askedFQDN: "kubernetes.default.svc.cluster.local",
		},
		{
			name:      "kubernetes.default.svc.cluster.local. absolute trailing-dot resolves",
			podNS:     "default",
			zone:      map[string]netip.Addr{"kubernetes.default.svc.cluster.local": kubeAddr},
			query:     "kubernetes.default.svc.cluster.local.",
			want:      kubeAddr,
			askedFQDN: "kubernetes.default.svc.cluster.local",
		},
		{
			name:      "kubernetes.default.svc partial form resolves via search expansion",
			podNS:     "default",
			zone:      map[string]netip.Addr{"kubernetes.default.svc.cluster.local": kubeAddr},
			query:     "kubernetes.default.svc",
			want:      kubeAddr,
			askedFQDN: "kubernetes.default.svc.cluster.local",
		},
		{
			// A pod in "default" reaches a service in "prod" via the <svc>.<ns> form.
			name:      "cross-namespace db.prod resolves to db.prod.svc.cluster.local",
			podNS:     "default",
			zone:      map[string]netip.Addr{"db.prod.svc.cluster.local": dbAddr},
			query:     "db.prod",
			want:      dbAddr,
			askedFQDN: "db.prod.svc.cluster.local",
		},
		{
			// "db" exists only in "prod"; a bare name stays in the pod's own namespace.
			name:         "bare db does NOT cross namespaces (k8s DNS contract)",
			podNS:        "default",
			zone:         map[string]netip.Addr{"db.prod.svc.cluster.local": dbAddr},
			query:        "db",
			wantNotFound: true,
			notAskedFQDN: "db.prod.svc.cluster.local",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stub := newStubDNS(t, tc.zone)
			defer stub.close()

			r := podResolver(t, tc.podNS, stub)
			addrs, err := r.LookupHost(context.Background(), tc.query)

			if tc.wantNotFound {
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("LookupHost(%q) from ns=%s err = %v, want ErrNotFound", tc.query, tc.podNS, err)
				}
			} else {
				if err != nil {
					t.Fatalf("LookupHost(%q) from ns=%s: %v", tc.query, tc.podNS, err)
				}
				if len(addrs) != 1 || addrs[0] != tc.want {
					t.Fatalf("LookupHost(%q) = %v, want [%v]", tc.query, addrs, tc.want)
				}
			}
			if tc.askedFQDN != "" && !stub.asked(tc.askedFQDN) {
				t.Fatalf("resolver never queried the canonical FQDN %q for %q", tc.askedFQDN, tc.query)
			}
			if tc.notAskedFQDN != "" && stub.asked(tc.notAskedFQDN) {
				t.Fatalf("resolver queried %q for bare name %q — a bare name must not cross namespaces", tc.notAskedFQDN, tc.query)
			}
		})
	}
}

// TestCandidateNamesCrossNamespaceContract documents, at the pure-expansion
// layer, the Kubernetes DNS namespace contract M2.2 relies on: kubernetes.default.svc
// and a cross-namespace <svc>.<ns> each expand to their canonical
// *.svc.cluster.local FQDN, while a BARE name only ever expands within the pod's
// OWN namespace — it never produces a candidate in another namespace.
func TestCandidateNamesCrossNamespaceContract(t *testing.T) {
	t.Parallel()
	cfg := PodDNSConfig("10.43.0.10", "cluster.local", "default") // pod in default ns

	t.Run("kubernetes.default.svc expands to its canonical FQDN", func(t *testing.T) {
		t.Parallel()
		cands := candidateNames(cfg, "kubernetes.default.svc")
		if !slices.Contains(cands, "kubernetes.default.svc.cluster.local") {
			t.Fatalf("candidates for kubernetes.default.svc missing canonical FQDN: %v", cands)
		}
	})

	t.Run("cross-namespace db.prod expands to db.prod.svc.cluster.local", func(t *testing.T) {
		t.Parallel()
		cands := candidateNames(cfg, "db.prod")
		if !slices.Contains(cands, "db.prod.svc.cluster.local") {
			t.Fatalf("candidates for db.prod missing cross-namespace FQDN: %v", cands)
		}
	})

	t.Run("bare name never expands into another namespace", func(t *testing.T) {
		t.Parallel()
		cands := candidateNames(cfg, "db")
		for _, c := range cands {
			if strings.Contains(c, ".prod.") || strings.HasSuffix(c, ".prod") {
				t.Fatalf("bare name db produced a cross-namespace candidate %q: %v", c, cands)
			}
		}
		// It must, however, expand within its own namespace.
		if !slices.Contains(cands, "db.default.svc.cluster.local") {
			t.Fatalf("bare name db did not expand within its own namespace: %v", cands)
		}
	})
}
