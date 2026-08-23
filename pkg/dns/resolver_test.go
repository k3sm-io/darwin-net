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
	"strings"
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

// TestLookupHostTruncatedTCPStaysTruncatedIsTempFail asserts that when even the
// TCP refetch comes back with the TC bit set (a malformed server), the lookup is
// a TRANSIENT failure (ErrTempFail), never a definitive miss — the answer set
// must fit a length-prefixed TCP message, so a still-truncated TCP response is
// not trustworthy. Mirrors the C shim's TEMPFAIL on TC-over-TCP.
func TestLookupHostTruncatedTCPStaysTruncatedIsTempFail(t *testing.T) {
	t.Parallel()
	stub := newStubDNS(t, map[string]netip.Addr{
		"big.default.svc.cluster.local": netip.MustParseAddr("10.43.0.7"),
	})
	defer stub.close()
	// UDP truncates → resolver refetches over TCP; TCP also truncates.
	stub.setTruncateUDP("big.default.svc.cluster.local")
	stub.setTruncateTCP("big.default.svc.cluster.local")

	r, err := NewResolver(stdConfig(), dialToStub(stub), WithTimeout(300*time.Millisecond))
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	_, err = r.LookupHost(context.Background(), "big")
	if !errors.Is(err, ErrTempFail) {
		t.Fatalf("LookupHost with TC-over-TCP err = %v, want ErrTempFail", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("TC-over-TCP collapsed into ErrNotFound: %v", err)
	}
	if !stub.askedTCP("big.default.svc.cluster.local") {
		t.Fatalf("resolver never attempted the TCP refetch")
	}
}

// TestLookupHostQueryCarriesEDNSOPT is the behavioral golden for the dual-authored
// OPT bytes: it asserts the resolver's query carries a well-formed EDNS0 OPT
// pseudo-RR advertising exactly EDNSUDPPayloadSize, pinning the Go path to the
// same wire advertisement the C shim emits.
func TestLookupHostQueryCarriesEDNSOPT(t *testing.T) {
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
	if _, err := r.LookupHost(context.Background(), "web"); err != nil {
		t.Fatalf("LookupHost(web): %v", err)
	}
	seen, size := stub.lastOPT()
	if !seen {
		t.Fatalf("resolver query carried no EDNS0 OPT record")
	}
	if size != EDNSUDPPayloadSize {
		t.Fatalf("EDNS0 OPT UDP payload size = %d, want %d", size, EDNSUDPPayloadSize)
	}
}

// TestUnencodableLabelDefinitiveMiss pins the two LABEL-shaped encode failures to
// the C shim's classification. dnsmessage.NewName bounds only a name's TOTAL
// length, so a name whose defect is a single label — 64 bytes, or zero bytes —
// passes construction and is rejected by Message.Pack instead; before the fix
// that Pack error was returned as a plain error, which lookupCandidate retried
// like a lost datagram and reported as ErrTempFail. The C shim's
// k3sm_encode_name rejects both at build time and returns K3SM_DNS_MISS with
// zero wire I/O. The assertion is the CLASSIFICATION (a definitive miss: nil
// error, no addrs) plus zero exchanges: an unencodable name must never reach the
// wire, and must never be retried.
//
// See also: TestDNSWireClassificationDifferential (differential_integration_test.go)
// asserts both cases against the REAL dylib.
func TestUnencodableLabelDefinitiveMiss(t *testing.T) {
	t.Parallel()

	t.Run("label over the 63-byte ceiling", func(t *testing.T) {
		// One 64-byte label (the wire ceiling is 63) in a name whose total is far
		// under 255 — so NewName accepts it and ONLY the Pack encode rejects it.
		fqdn := strings.Repeat("x", 64) + ".test.invalid"
		if n := len(ensureFQDN(fqdn)); n > 255 {
			t.Fatalf("fixture name is %d bytes; it must stay <=255 so NewName is not the rejecting step", n)
		}
		assertUnencodableDefinitiveMiss(t, fqdn)
	})

	t.Run("zero-length interior label", func(t *testing.T) {
		// "a..b": Pack fails with errZeroSegLen. The C shim used to SKIP an empty
		// label, collapsing this to "a.b" and querying a name the caller never
		// asked for; k3sm_encode_name now rejects it, so both engines agree.
		assertUnencodableDefinitiveMiss(t, "a..b.test.invalid")
	})
}

// assertUnencodableDefinitiveMiss asserts the resolver classifies fqdn as a
// DEFINITIVE miss — at the per-candidate altitude and at the caller-visible
// LookupHost altitude — with zero exchanges on the wire.
func assertUnencodableDefinitiveMiss(t *testing.T, fqdn string) {
	t.Helper()
	stub := newStubDNS(t, map[string]netip.Addr{})
	defer stub.close()

	// dials counts every exchange the resolver attempts. It is written only from
	// the resolver's synchronous dial seam on this goroutine, so it needs no lock.
	dials := 0
	counting := withDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
		dials++
		d := net.Dialer{}
		return d.DialContext(ctx, network, stub.addr())
	})
	r, err := NewResolver(stdConfig(), counting, WithTimeout(200*time.Millisecond))
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	addrs, err := r.lookupCandidate(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("lookupCandidate(%q) err = %v, want a DEFINITIVE miss (nil error, no addrs)", fqdn, err)
	}
	if len(addrs) != 0 {
		t.Fatalf("lookupCandidate(%q) = %v, want no addresses", fqdn, addrs)
	}
	if dials != 0 {
		t.Fatalf("resolver attempted %d exchange(s) for an unencodable name; want 0", dials)
	}
	if stub.asked(fqdn) {
		t.Fatalf("stub received a query for an unencodable name")
	}

	// The caller-visible consequence: ErrNotFound (the name cannot exist), never
	// ErrTempFail (which would make a pod retry a name that can never resolve).
	_, err = r.LookupHost(context.Background(), fqdn+".")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("LookupHost(unencodable) err = %v, want ErrNotFound", err)
	}
	if errors.Is(err, ErrTempFail) {
		t.Fatalf("unencodable name reported as transient: %v", err)
	}
	if dials != 0 {
		t.Fatalf("LookupHost attempted %d exchange(s) for an unencodable name; want 0", dials)
	}
}

// TestLookupHostClosedPortIsTempFail points the resolver at a closed loopback
// port: a connected-UDP exchange gets an immediate ECONNREFUSED, which is a
// TRANSIENT failure (ErrTempFail), never ErrNotFound — the Go analog of the
// shim's EAI_AGAIN when the cluster resolver is unreachable.
func TestLookupHostClosedPortIsTempFail(t *testing.T) {
	t.Parallel()
	// Reserve then release a loopback UDP port so it is (near-certainly) closed.
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("reserve closed port: %v", err)
	}
	closedAddr := c.LocalAddr().String()
	_ = c.Close()

	dialClosed := withDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, network, closedAddr)
	})
	r, err := NewResolver(stdConfig(), dialClosed, WithTimeout(300*time.Millisecond))
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	_, err = r.LookupHost(context.Background(), "web")
	if !errors.Is(err, ErrTempFail) {
		t.Fatalf("LookupHost against a closed port err = %v, want ErrTempFail", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("ECONNREFUSED collapsed into ErrNotFound: %v", err)
	}
}
