//go:build integration

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

// Wire-classification differential between the two resolvers k3sm ships.
//
// pkg/dns/resolver.go (Go, the reference) and shim/getaddrinfo_shim.c (the C
// DYLD interposer pods actually load) are two INDEPENDENT parsers of the same
// DNS wire format, and they must agree on the one decision that matters: is a
// response a HIT, a DEFINITIVE MISS, or a TRANSIENT failure? A miss classified
// as transient makes a pod retry a name that can never resolve; a transient
// classified as a miss turns a resolver blip into a confident "no such host".
// The sibling drift guards in env_test.go (TestShimEnvNamesMatchC,
// TestShimMaxSearchMatchesC, TestShimAttemptsMatchesC, TestShimEDNSSizeMatchesC)
// bind the two sides' CONSTANTS by reading the .c as text; this file binds their
// BEHAVIOUR by running both against the same bytes. They are complements, not
// duplicates — neither subsumes the other, so do not delete one as redundant.
//
// Run with:
//
//	CGO_ENABLED=0 go test -tags integration -run TestDNSWireClassificationDifferential ./pkg/dns/
//
// # Design
//
// Both engines are read at the SAME ALTITUDE — the per-candidate three-way
// verdict, before any candidate-walk policy:
//
//   - Go side: lookupCandidate's outcome, driven through the existing withDialer
//     seam (addresses => HIT, nil error with no addresses => definitive MISS, an
//     ErrTempFail wrap => TEMPFAIL).
//   - C side: the REAL shipped dylib (built by hack/build-shim.sh, unmodified),
//     injected with DYLD_INSERT_LIBRARIES into the probe binary, with its verdict
//     read from the K3SM_DNS_DEBUG stderr trace.
//
// The verdict is NEVER read from the shim's final EAI_*/addrinfo result: after a
// definitive MISS the shim falls through to the real host getaddrinfo
// (getaddrinfo_shim.c, the trailing "cluster resolver missed all N candidate(s)"
// DEFER), so the process's ultimate answer depends on ambient network state. The
// trace fires BEFORE that fallthrough, so the asserted verdict stays hermetic
// even though the probe process may perform a live lookup afterwards. Fixture
// hostnames all sit under RFC 2606 ".invalid" to bound that fallthrough to a name
// no real resolver can answer.
//
// # Caveat 1 — trace-wording coupling
//
// The C side's verdict is parsed out of PRIVATE diagnostic log text
// ("k3sm-dns:   query <cand> @ <ip>:<port> -> HIT|miss|TEMPFAIL"), which is not
// an API. Reword that fprintf and this gate stops seeing a verdict — keep the two
// in lockstep, the same coupling caveat k3sm's reapAlertPrefix carries. traceRE
// below is the single place the wording is encoded, and the test FAILS (rather
// than passing vacuously) when it matches no line.
//
// # Caveat 2 — a shared blind spot
//
// Neither engine reads the EDNS0 extended RCODE: the Go side takes
// dnsmessage.Header.RCode (the low 4 bits) and the C side takes rbuf[3]&0x0f,
// and both ignore the OPT TTL's upper byte. A BADVERS/extended-rcode response is
// therefore misclassified IDENTICALLY on both sides, and this differential would
// still be green. Identity here proves PARITY, not correctness.
//
// # Fixtures
//
// testdata/<case>.golden.wire is the UDP response TEMPLATE for <case>; a case
// that refetches over TCP additionally carries testdata/<case>.tcp.golden.wire
// as the TCP response. They are response templates, not captures: the stub
// patches the 2-byte ID field of each one from the ID of the query that arrived.
// That patch is what makes a single fixture serve BOTH engines, which do not
// agree on query IDs — the C shim hardcodes 0x1234 (getaddrinfo_shim.c
// k3sm_build_query) while the Go resolver hashes the name (dnsQueryID). The one
// exception is malformed_wrongid, where the stub deliberately answers with the
// incoming ID XOR 0xFFFF, i.e. wrong relative to whatever each engine sent.
//
// TWO cases are INPUT-ONLY and deliberately have NO .golden.wire fixture — do
// not go looking for one: unencodable_label_gt63 and unencodable_total_gt255 are
// rejected at query-encode time, so no response is ever served.
package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// wireVerdict is the three-way per-candidate classification both engines produce.
type wireVerdict int

const (
	verdictHit wireVerdict = iota
	verdictMiss
	verdictTempFail
)

func (v wireVerdict) String() string {
	switch v {
	case verdictHit:
		return "HIT"
	case verdictMiss:
		return "MISS"
	case verdictTempFail:
		return "TEMPFAIL"
	}
	return fmt.Sprintf("wireVerdict(%d)", int(v))
}

// traceRE extracts the C shim's per-candidate verdict from its K3SM_DNS_DEBUG
// stderr trace. It is the ONE place the private log wording is encoded (see
// Caveat 1 in the file comment); the format is the fprintf in
// shim/getaddrinfo_shim.c's k3sm_getaddrinfo candidate loop:
//
//	"k3sm-dns:   query %s @ %s:%s -> %s\n"   with %s in {"HIT", "miss", "TEMPFAIL"}
//
// The shim prints exactly ONE such line per CANDIDATE, after its retry loop, so
// the captured verdict is the FINAL one — a TEMPFAIL that took K3SM_DNS_ATTEMPTS
// tries prints once, and a TC-on-UDP answer refetched over TCP prints once, as
// the HIT the TCP response yielded (the refetch happens inside k3sm_query_a,
// below the trace point, and emits no line of its own).
var traceRE = regexp.MustCompile(`(?m)^k3sm-dns:\s+query (\S+) @ (\S+) -> (HIT|miss|TEMPFAIL)$`)

// wireFixture is one case's served response templates.
type wireFixture struct {
	udp     []byte
	tcp     []byte // nil when the case never refetches over TCP
	wrongID bool   // answer with the incoming ID XOR 0xFFFF
}

// wireQuery is one query the stub observed.
type wireQuery struct {
	transport string
	name      string
}

// templateDNS is a stub DNS server that answers from raw wire TEMPLATES rather
// than from a name->addr zone (the job stubDNS in stubserver_test.go does for the
// unit tier). Serving fixed bytes is what lets one fixture drive two independent
// parsers: the template is byte-identical for both engines, with only the 2-byte
// ID patched per query. A query for a name with no fixture is answered with a
// synthesized NXDOMAIN, which only the pinned C-side truncation divergence below
// ever reaches.
type templateDNS struct {
	udp    *net.UDPConn
	tcpLn  net.Listener
	byHost map[string]wireFixture

	mu      sync.Mutex
	queries []wireQuery

	wg   sync.WaitGroup
	done chan struct{}
}

// newTemplateDNS starts a template stub on an ephemeral loopback port (the same
// port for UDP and TCP).
func newTemplateDNS(t *testing.T, byHost map[string]wireFixture) *templateDNS {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("template stub udp listen: %v", err)
	}
	tcpLn, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		_ = udp.Close()
		t.Fatalf("template stub tcp listen: %v", err)
	}
	s := &templateDNS{udp: udp, tcpLn: tcpLn, byHost: byHost, done: make(chan struct{})}
	s.wg.Add(2)
	go s.serveUDP()
	go s.serveTCP()
	return s
}

func (s *templateDNS) addr() string { return s.udp.LocalAddr().String() }

func (s *templateDNS) port() int { return s.udp.LocalAddr().(*net.UDPAddr).Port }

func (s *templateDNS) close() {
	close(s.done)
	_ = s.udp.Close()
	_ = s.tcpLn.Close()
	s.wg.Wait()
}

// observed returns the queries the stub received, in arrival order.
func (s *templateDNS) observed() []wireQuery {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]wireQuery, len(s.queries))
	copy(out, s.queries)
	return out
}

func (s *templateDNS) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 4096)
	for {
		select {
		case <-s.done:
			return
		default:
		}
		_ = s.udp.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, raddr, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		resp, ok := s.respond(buf[:n], "udp")
		if !ok {
			continue
		}
		_, _ = s.udp.WriteToUDP(resp, raddr)
	}
}

func (s *templateDNS) serveTCP() {
	defer s.wg.Done()
	for {
		conn, err := s.tcpLn.Accept()
		if err != nil {
			return
		}
		func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			var lb [2]byte
			if _, err := io.ReadFull(conn, lb[:]); err != nil {
				return
			}
			query := make([]byte, binary.BigEndian.Uint16(lb[:]))
			if _, err := io.ReadFull(conn, query); err != nil {
				return
			}
			resp, ok := s.respond(query, "tcp")
			if !ok {
				return
			}
			framed := make([]byte, 2+len(resp))
			binary.BigEndian.PutUint16(framed, uint16(len(resp)))
			copy(framed[2:], resp)
			_, _ = conn.Write(framed)
		}()
	}
}

// respond logs the query and returns the ID-patched template for its name.
func (s *templateDNS) respond(query []byte, transport string) ([]byte, bool) {
	qname, qend, ok := wireQName(query)
	if !ok {
		return nil, false
	}
	s.mu.Lock()
	s.queries = append(s.queries, wireQuery{transport: transport, name: qname})
	fx, known := s.byHost[qname]
	s.mu.Unlock()

	id := binary.BigEndian.Uint16(query[0:2])
	if !known {
		return synthNXDomain(query, qend, id), true
	}
	tpl := fx.udp
	if transport == "tcp" && fx.tcp != nil {
		tpl = fx.tcp
	}
	resp := make([]byte, len(tpl))
	copy(resp, tpl)
	if fx.wrongID {
		id ^= 0xFFFF
	}
	// The ID patch: the fixture is a TEMPLATE, and the two engines send different
	// IDs for the same name (C: hardcoded 0x1234; Go: dnsQueryID's per-name hash).
	if len(resp) >= 2 {
		binary.BigEndian.PutUint16(resp[0:2], id)
	}
	return resp, true
}

// synthNXDomain builds a minimal NXDOMAIN answer echoing the query's question
// section. Only the C shim's over-long-name TRUNCATION (pinned below) reaches it.
func synthNXDomain(query []byte, qend int, id uint16) []byte {
	resp := make([]byte, 12, 12+(qend-12))
	binary.BigEndian.PutUint16(resp[0:2], id)
	resp[2] = 0x81 // QR=1, RD=1
	resp[3] = 0x83 // RA=1, RCODE=3 (NXDOMAIN)
	binary.BigEndian.PutUint16(resp[4:6], 1)
	return append(resp, query[12:qend]...)
}

// wireQName decodes a query's question name and returns it plus the offset just
// past the question section. It walks the labels by hand rather than through
// dnsmessage: the C shim can emit a 255-byte name that the dnsmessage Name type
// refuses to hold, and the stub must still observe and log that query.
func wireQName(msg []byte) (name string, qend int, ok bool) {
	if len(msg) < 12 {
		return "", 0, false
	}
	var labels []string
	off := 12
	for off < len(msg) && msg[off] != 0 {
		n := int(msg[off])
		if n > 63 || off+1+n > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[off+1:off+1+n]))
		off += 1 + n
	}
	if off >= len(msg) {
		return "", 0, false
	}
	off++ // root label
	if off+4 > len(msg) {
		return "", 0, false
	}
	return toLowerASCII(strings.Join(labels, ".")), off + 4, true
}

// diffCase is one row of the differential: a name, the verdict BOTH engines must
// reach for it, and how it is served.
type diffCase struct {
	name string // subtest name; also the testdata/<name>.golden.wire basename
	host string // the queried name, without a trailing dot
	want wireVerdict
	// wire is false for the two INPUT-ONLY cases, which are rejected at
	// query-encode time and therefore have no fixture file.
	wire    bool
	tcpWire bool // a testdata/<name>.tcp.golden.wire also exists
	wrongID bool
	why     string
}

func differentialCases() []diffCase {
	return []diffCase{
		{name: "nxdomain", host: "nxdomain.test.invalid", want: verdictMiss, wire: true,
			why: "RCODE=NXDOMAIN: the server answered and the name does not exist"},
		{name: "nodata", host: "nodata.test.invalid", want: verdictMiss, wire: true,
			why: "NOERROR with zero answers (NODATA) — the SEPARATE ancount<1 branch in the C parser"},
		{name: "servfail", host: "servfail.test.invalid", want: verdictTempFail, wire: true,
			why: "SERVFAIL is upstream trouble, never 'no such host'"},
		{name: "tc_udp", host: "tc-udp.test.invalid", want: verdictHit, wire: true, tcpWire: true,
			why: "TC on the UDP response, clean answer on the TCP refetch (RFC 1035 4.2.2)"},
		{name: "tc_tcp", host: "tc-tcp.test.invalid", want: verdictTempFail, wire: true, tcpWire: true,
			why: "TC still set on the TCP response is malformed, never a definitive result"},
		{name: "malformed_short", host: "malformed-short.test.invalid", want: verdictTempFail, wire: true,
			why: "a response shorter than a DNS header cannot be classified"},
		{name: "malformed_wrongid", host: "malformed-wrongid.test.invalid", want: verdictTempFail, wire: true, wrongID: true,
			why: "an answer bearing someone else's ID is not this query's answer"},
		{name: "malformed_nonresponse", host: "malformed-nonresponse.test.invalid", want: verdictTempFail, wire: true,
			why: "QR=0: a query echoed back is not an answer"},
		{name: "cname_then_a", host: "cname-then-a.test.invalid", want: verdictHit, wire: true,
			why: "a CNAME ahead of the A record must be skipped, not mistaken for the answer"},
		{name: "a_in_additional_only", host: "a-in-additional-only.test.invalid", want: verdictMiss, wire: true,
			why: "an A record in the Additional section is not an answer; neither side reads Additionals"},
		{name: "unencodable_label_gt63", host: strings.Repeat("x", 64) + ".test.invalid", want: verdictMiss,
			why: "INPUT-ONLY (no fixture): a 64-byte label cannot be encoded, so the name can never resolve"},
		{name: "unencodable_total_gt255", host: overlongName(), want: verdictMiss,
			why: "INPUT-ONLY (no fixture): a name over 255 bytes cannot be encoded"},
	}
}

// overlongName builds a name whose ONLY defect is its total length: every label
// is 60 bytes (well under the 63-byte ceiling), but the whole name exceeds the
// 255-byte total, so it is the total-length branch that rejects it.
func overlongName() string {
	n := strings.Repeat(strings.Repeat("a", 60)+".", 4) + strings.Repeat("b", 20) + ".invalid"
	if len(ensureFQDN(n)) <= 255 {
		panic("overlongName fixture is not over 255 bytes")
	}
	return n
}

// loadFixtures reads the case table's wire templates from testdata/.
func loadFixtures(t *testing.T, cases []diffCase) map[string]wireFixture {
	t.Helper()
	out := make(map[string]wireFixture, len(cases))
	for _, c := range cases {
		if !c.wire {
			continue
		}
		fx := wireFixture{udp: readFixture(t, c.name+".golden.wire"), wrongID: c.wrongID}
		if c.tcpWire {
			fx.tcp = readFixture(t, c.name+".tcp.golden.wire")
		}
		out[c.host] = fx
	}
	return out
}

func readFixture(t *testing.T, base string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", base))
	if err != nil {
		t.Fatalf("read wire fixture %s: %v", base, err)
	}
	return b
}

// goVerdict runs the Go reference resolver's lookupCandidate against the stub and
// maps its outcome onto the three-way verdict.
func goVerdict(t *testing.T, stub *templateDNS, fqdn string) wireVerdict {
	t.Helper()
	r, err := NewResolver(stdConfig(), withDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, network, stub.addr())
	}), WithTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	addrs, err := r.lookupCandidate(context.Background(), fqdn)
	switch {
	case err != nil && errors.Is(err, ErrTempFail):
		return verdictTempFail
	case err != nil:
		t.Fatalf("lookupCandidate(%q) returned a non-transient hard error: %v", fqdn, err)
		return verdictTempFail
	case len(addrs) > 0:
		return verdictHit
	default:
		return verdictMiss
	}
}

// shimVerdict runs the probe binary with the REAL dylib injected and reads the
// per-candidate verdict out of the shim's K3SM_DNS_DEBUG trace. It returns the
// verdict and the candidate name the shim reported querying. The probe's own exit
// status is deliberately ignored: after a MISS or an external TEMPFAIL the shim
// defers to the host resolver, whose answer is ambient (see the file comment).
func shimVerdict(t *testing.T, dylib, probe string, stub *templateDNS, host string) (wireVerdict, string) {
	t.Helper()
	// The name is passed ABSOLUTE (trailing dot) so the shim's ndots/search
	// expansion yields exactly ONE candidate — hence exactly one trace line, at
	// the same altitude as the single lookupCandidate call on the Go side.
	cmd := exec.Command(probe, host+".")
	cmd.Env = append(os.Environ(),
		EnvDNSServer+"=127.0.0.1",
		EnvDNSPort+"="+strconv.Itoa(stub.port()),
		EnvDNSDomain+"=cluster.local",
		EnvDNSSearch+"="+strings.Join(stdSearch(), " "),
		EnvDNSNdots+"=5",
		EnvDNSDebug+"=1",
		"DYLD_INSERT_LIBRARIES="+dylib,
	)
	out, _ := cmd.CombinedOutput()
	m := traceRE.FindAllStringSubmatch(string(out), -1)
	if len(m) != 1 {
		t.Fatalf("want exactly 1 shim verdict trace line for %q, got %d — the shim's K3SM_DNS_DEBUG wording drifted from traceRE, or the dylib did not load:\n%s",
			host, len(m), out)
	}
	cand, verdict := m[0][1], m[0][3]
	switch verdict {
	case "HIT":
		return verdictHit, cand
	case "miss":
		return verdictMiss, cand
	case "TEMPFAIL":
		return verdictTempFail, cand
	}
	t.Fatalf("unparsed shim verdict %q", verdict)
	return verdictTempFail, cand
}

// TestDNSWireClassificationDifferential is the B126 gate: it feeds each golden
// response template through BOTH resolvers and asserts they reach the SAME
// three-way verdict — the property the constant-level drift guards in
// env_test.go cannot express.
func TestDNSWireClassificationDifferential(t *testing.T) {
	// Deliberate deviation from TestGetaddrinfoShimResolvesViaStub's t.Skip("clang
	// not available") precedent: this gate is the BACKSTOP for C<->Go behavioural
	// drift, and a skipped backstop reads exactly like a passing one in CI output.
	// A missing toolchain is an environment defect to fix, not a result to report.
	if _, err := exec.LookPath("clang"); err != nil {
		t.Fatalf("clang is required for the C<->Go wire differential (this gate must not be skipped): %v", err)
	}

	cases := differentialCases()
	fixtures := loadFixtures(t, cases)
	dylib := buildShim(t)
	probe := buildProbe(t)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Each engine gets its own stub instance so the observed query log is
			// unambiguously attributable to one side.
			goStub := newTemplateDNS(t, fixtures)
			defer goStub.close()
			cStub := newTemplateDNS(t, fixtures)
			defer cStub.close()

			goGot := goVerdict(t, goStub, c.host)
			cGot, cand := shimVerdict(t, dylib, probe, cStub, c.host)
			if goGot != cGot {
				t.Fatalf("C<->Go wire-classification drift on %s (%s):\n  Go reference resolver: %v\n  C getaddrinfo shim:    %v",
					c.name, c.why, goGot, cGot)
			}
			if goGot != c.want {
				t.Fatalf("both engines classify %s (%s) as %v, want %v — parity held but the shared verdict is wrong",
					c.name, c.why, goGot, c.want)
			}
			// Both engines must have judged the SAME name. (The one case where the
			// shim reports a different candidate is the truncation divergence pinned
			// below, which is why it is excluded here.)
			if c.name != "unencodable_total_gt255" && cand != c.host {
				t.Fatalf("shim traced candidate %q, want %q — the search expansion did not collapse to one candidate", cand, c.host)
			}

			switch c.name {
			case "unencodable_label_gt63":
				// Both sides reject at encode time, so NEITHER may touch the wire:
				// the Go resolver's Message.Pack fails on the 64-byte label and the
				// shim's k3sm_encode_name returns -1, each yielding a definitive
				// miss with zero I/O.
				assertNoQueries(t, "Go reference resolver", goStub)
				assertNoQueries(t, "C getaddrinfo shim", cStub)
			case "unencodable_total_gt255":
				assertNoQueries(t, "Go reference resolver", goStub)
				// KNOWN DIVERGENCE, pinned here rather than hidden: the C shim does
				// NOT reject an over-long name. k3sm_candidates copies each candidate
				// with snprintf(out[n], K3SM_MAX_NAME, ...), which TRUNCATES at 255
				// bytes, and the truncated name encodes fine — so the shim puts a
				// query for a DIFFERENT name than the caller asked for on the wire
				// (which could return a wrong HIT if that truncated name exists),
				// while the Go resolver sends nothing. The verdicts still agree here
				// only because the stub answers the unknown truncated name NXDOMAIN.
				// The C shim is out of scope for this change; when it is fixed to
				// reject over-long names, this assertion goes red and should collapse
				// into the zero-queries case above.
				obs := cStub.observed()
				if len(obs) != 1 {
					t.Fatalf("C shim sent %d queries for an over-long name, want exactly 1 (the pinned truncation divergence): %v", len(obs), obs)
				}
				if obs[0].name == c.host || !strings.HasPrefix(c.host, obs[0].name) {
					t.Fatalf("C shim queried %q (%d bytes); want a strict K3SM_MAX_NAME truncation of the %d-byte requested name",
						obs[0].name, len(obs[0].name), len(c.host))
				}
			}
		})
	}
}

// assertNoQueries fails when side put anything on the wire.
func assertNoQueries(t *testing.T, side string, stub *templateDNS) {
	t.Helper()
	if obs := stub.observed(); len(obs) != 0 {
		t.Fatalf("%s queried an unencodable name (%v); such a name can never resolve, so it must never reach the wire", side, obs)
	}
}
