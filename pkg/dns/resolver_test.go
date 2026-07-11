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

// TestLookupHostRetriesLostDatagram asserts a single lost UDP datagram does not
// fail the candidate: the resolver retries (queryAttempts) and resolves the SAME
// candidate, rather than sliding past it to a later search domain — which is how
// one dropped packet used to turn into a wrong NXDOMAIN.
func TestLookupHostRetriesLostDatagram(t *testing.T) {
	t.Parallel()
	want := netip.MustParseAddr("10.43.0.42")
	stub := newStubDNS(t, map[string]netip.Addr{
		"web.default.svc.cluster.local": want,
	})
	defer stub.close()
	stub.dropNext("web.default.svc.cluster.local", 1)

	r, err := NewResolver(stdConfig(), dialToStub(stub), WithTimeout(200*time.Millisecond))
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	addrs, err := r.LookupHost(context.Background(), "web")
	if err != nil {
		t.Fatalf("LookupHost(web) with one dropped datagram: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != want {
		t.Fatalf("LookupHost = %v, want [%v]", addrs, want)
	}
}

// TestLookupHostServfailIsTempFailNotNotFound asserts SERVFAIL surfaces as
// ErrTempFail and STOPS the candidate walk: every candidate asks the same
// server, so continuing past a failing candidate can only produce a wrong
// answer from a later search domain (or a false "no such host").
func TestLookupHostServfailIsTempFailNotNotFound(t *testing.T) {
	t.Parallel()
	// The later candidate exists — a resolver that slid past the SERVFAIL
	// would "resolve" kube-dns from the wrong search domain.
	stub := newStubDNS(t, map[string]netip.Addr{
		"kube-dns.svc.cluster.local": netip.MustParseAddr("10.43.0.99"),
	})
	defer stub.close()
	stub.setServfail("kube-dns.default.svc.cluster.local")

	r, err := NewResolver(stdConfig(), dialToStub(stub), WithTimeout(time.Second))
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	_, err = r.LookupHost(context.Background(), "kube-dns")
	if !errors.Is(err, ErrTempFail) {
		t.Fatalf("LookupHost with SERVFAIL err = %v, want ErrTempFail", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("SERVFAIL collapsed into ErrNotFound: %v", err)
	}
	if stub.asked("kube-dns.svc.cluster.local") {
		t.Fatalf("resolver walked past a SERVFAIL candidate to a later search domain")
	}
}

// TestLookupHostTruncatedRefetchesTCP asserts a TC-bit UDP response triggers a
// TCP refetch of the same query (RFC 1035 §4.2.2) and the lookup returns the
// full answer from the TCP path.
func TestLookupHostTruncatedRefetchesTCP(t *testing.T) {
	t.Parallel()
	want := netip.MustParseAddr("10.43.0.7")
	stub := newStubDNS(t, map[string]netip.Addr{
		"big.default.svc.cluster.local": want,
	})
	defer stub.close()
	stub.setTruncateUDP("big.default.svc.cluster.local")

	r, err := NewResolver(stdConfig(), dialToStub(stub), WithTimeout(time.Second))
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	addrs, err := r.LookupHost(context.Background(), "big")
	if err != nil {
		t.Fatalf("LookupHost(big) with truncated UDP: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != want {
		t.Fatalf("LookupHost = %v, want [%v]", addrs, want)
	}
	if !stub.askedTCP("big.default.svc.cluster.local") {
		t.Fatalf("resolver never re-fetched the truncated answer over TCP")
	}
}
