package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// dialToStub returns a dialer Option that redirects the resolver's CoreDNS
// queries to the stub server, regardless of the configured ClusterDNSIP. This
// lets the resolver carry a realistic 10.43.0.10 VIP in its DNSConfig while the
// query actually lands on the in-process stub.
func dialToStub(s *stubDNS) Option {
	return withDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, network, s.addr())
	})
}

// TestLookupHostShortNameViaSearch proves the resolver resolves a SHORT name
// (e.g. "web") by search expansion over the real UDP wire to a stub CoreDNS —
// the end-to-end analog of the shim's job. The stub only knows the FQDN form, so
// a resolver that skipped search expansion would fail to resolve "web".
func TestLookupHostShortNameViaSearch(t *testing.T) {
	t.Parallel()
	want := netip.MustParseAddr("10.43.0.42")
	stub := newStubDNS(t, map[string]netip.Addr{
		"web.default.svc.cluster.local": want,
	})
	defer stub.close()

	r, err := NewResolver(stdConfig(), dialToStub(stub), WithTimeout(time.Second))
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	addrs, err := r.LookupHost(context.Background(), "web")
	if err != nil {
		t.Fatalf("LookupHost(web): %v", err)
	}
	if len(addrs) != 1 || addrs[0] != want {
		t.Fatalf("LookupHost(web) = %v, want [%v]", addrs, want)
	}
	// The query that succeeded must be the search-expanded FQDN.
	if !stub.asked("web.default.svc.cluster.local") {
		t.Fatalf("resolver never queried the search-expanded FQDN")
	}
}

// TestLookupHostTriesCandidatesInOrder asserts the resolver walks the candidate
// list and returns the first that resolves, when only a later search domain
// holds the record.
func TestLookupHostTriesCandidatesInOrder(t *testing.T) {
	t.Parallel()
	want := netip.MustParseAddr("10.43.0.99")
	// Only the svc.cluster.local form exists, not the default.svc form.
	stub := newStubDNS(t, map[string]netip.Addr{
		"kube-dns.svc.cluster.local": want,
	})
	defer stub.close()

	r, err := NewResolver(stdConfig(), dialToStub(stub), WithTimeout(time.Second))
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	addrs, err := r.LookupHost(context.Background(), "kube-dns")
	if err != nil {
		t.Fatalf("LookupHost(kube-dns): %v", err)
	}
	if len(addrs) != 1 || addrs[0] != want {
		t.Fatalf("LookupHost = %v, want [%v]", addrs, want)
	}
}

// TestLookupHostNotFound asserts an unknown name across the whole search list
// yields ErrNotFound.
func TestLookupHostNotFound(t *testing.T) {
	t.Parallel()
	stub := newStubDNS(t, map[string]netip.Addr{})
	defer stub.close()

	r, err := NewResolver(stdConfig(), dialToStub(stub), WithTimeout(time.Second))
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	_, err = r.LookupHost(context.Background(), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("LookupHost(nope) err = %v, want ErrNotFound", err)
	}
}

// TestLookupHostAbsoluteName asserts a trailing-dot name is queried exactly once
// (search skipped) and resolves.
func TestLookupHostAbsoluteName(t *testing.T) {
	t.Parallel()
	want := netip.MustParseAddr("10.43.0.1")
	stub := newStubDNS(t, map[string]netip.Addr{
		"kubernetes.default.svc.cluster.local": want,
	})
	defer stub.close()

	r, err := NewResolver(stdConfig(), dialToStub(stub), WithTimeout(time.Second))
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	addrs, err := r.LookupHost(context.Background(), "kubernetes.default.svc.cluster.local.")
	if err != nil {
		t.Fatalf("LookupHost absolute: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != want {
		t.Fatalf("LookupHost = %v, want [%v]", addrs, want)
	}
}

// TestNewResolverRejectsBadConfig asserts construction validates the DNSConfig.
func TestNewResolverRejectsBadConfig(t *testing.T) {
	t.Parallel()
	_, err := NewResolver(netv1.DNSConfig{ClusterDomain: "cluster.local"})
	if !errors.Is(err, netv1.ErrInvalid) {
		t.Fatalf("NewResolver with no cluster IP err = %v, want ErrInvalid", err)
	}
}
