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
// hostnames sit under RFC 2606 ".invalid" to bound that fallthrough to a name no
// real resolver can answer — with one deliberate exception, cluster_named_service,
// whose name must be under the cluster domain to classify cluster-scoped at all,
// and which HITs and therefore never falls through.
//
// # Two altitudes: single-candidate rows and multi-candidate rows
//
// Most rows are SINGLE-CANDIDATE: the probe is handed an ABSOLUTE name (trailing
// dot) so the shim's expansion collapses to one candidate and the comparison is
// one verdict against one lookupCandidate call. A few rows are opt-in
// MULTI-CANDIDATE (diffCase.multi): the probe is handed the BARE name with a
// per-case search/ndots env, every trace line is collected, and the two engines'
// per-candidate verdict MAPS — keyed by candidate NAME, never by index — are
// compared. Name-keying is what makes an ordering bug fail distinctly (two
// missing keys) instead of quietly swapping two equal verdicts.
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
// # Caveat 3 — the EXTERNAL + named-service DEFER branch is not differentiable
//
// One branch of the shim's candidate walk is deliberately EXCLUDED from this
// gate: an EXTERNAL candidate (dotted, under no cluster/search domain) combined
// with a NAMED service ("http"), which defers the whole call to the system
// resolver BEFORE querying. Two independent reasons, either sufficient. It emits
// a "DEFER … external candidate … with named service" line and NO per-candidate
// verdict line, so there is no C-side verdict to read at this file's altitude.
// And the Go reference has no analog to compare it against: pkg/dns models
// neither a service argument nor a host-resolver fallthrough, so covering it
// would mean inventing a Go-side verdict the reference resolver does not
// produce — the opposite of what a differential is for. That branch is pinned
// instead, C-side only, by TestGetaddrinfoShimNamedService/"named service on an
// external name defers to the system resolver" (shim_integration_test.go). The
// CLUSTER half of the same named_service branch IS differentiable — a
// cluster-scoped candidate is queried rather than deferred — and cluster_named_service
// covers it here.
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
// SEVEN cases are INPUT-ONLY and deliberately have NO .golden.wire fixture — do
// not go looking for one: unencodable_label_gt63, unencodable_total_gt255,
// unencodable_empty_label, unencodable_empty_name, boundary_over_max_name and
// plain_over_boundary are rejected at query-encode time on BOTH engines, so no
// response is ever served; search_suffix_over_boundary is rejected on its
// SUFFIXED candidate only and its bare candidate is answered by the synthesized
// NXDOMAIN below.
//
// boundary_max_name has no fixture either, for a different reason: it is the
// name one byte SHORTER than boundary_over_max_name, it does reach the wire on
// both engines, and the stub's synthesized NXDOMAIN (below) is the answer. The
// two together pin the shared presentation-length boundary from both sides.
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
	"reflect"
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
//
// The candidate group is (\S*), not (\S+): the DEGENERATE EMPTY candidate (the
// request ".", whose trailing dot k3sm_candidates strips to "") prints nothing
// between the two spaces, and (\S+) matches that line ZERO times — which the
// callers below report as "the dylib did not load", masking the real verdict.
// (\S*) is a STRICT SUPERSET of (\S+) here: every other candidate this file
// produces is non-empty, so no pre-existing row's parse changes.
var traceRE = regexp.MustCompile(`(?m)^k3sm-dns:\s+query (\S*) @ (\S+) -> (HIT|miss|TEMPFAIL)$`)

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
// synthesized NXDOMAIN; the cases that reach it are boundary_max_name — whose
// point is that a name at exactly the shared length ceiling still gets encoded
// and asked on both engines — and search_suffix_over_boundary's bare candidate.
//
// That catch-all is also why the zero-query assertions matter: an unencodable
// name that WAS put on the wire would come back NXDOMAIN and land on the same
// MISS verdict as one that was never sent, so verdict parity alone would be
// vacuously green. Only stub.observed() can tell the two apart.
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
// section. Only boundary_max_name — the fixture-less case that deliberately DOES
// reach the wire on both engines — is answered from here.
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
	// want is the verdict both engines must reach for a SINGLE-CANDIDATE row. A
	// multi row's per-candidate wants live in multi.want and this field is never
	// read for it — runMultiCandidate returns before the single-candidate
	// comparison. Do not overload it.
	want wireVerdict
	// wire is false for the INPUT-ONLY cases (rejected at query-encode time on
	// both engines), for boundary_max_name (answered by the stub's synthesized
	// NXDOMAIN), and for every multi row; none of them has a fixture file.
	wire    bool
	tcpWire bool // a testdata/<name>.tcp.golden.wire also exists
	wrongID bool
	// probeService, when non-empty, is passed to the probe as its SERVICE argv —
	// the getaddrinfo `service` argument. Empty (the 15 pre-existing rows) means
	// the probe is invoked with a name only, exactly as before.
	probeService string
	// multi, when non-nil, makes this an opt-in MULTI-CANDIDATE row: the probe
	// gets the BARE host with multi's own search/ndots env and both engines are
	// read per candidate. host keeps its meaning (the queried name); the fixture
	// fields above must stay unset.
	multi *multiCand
	why   string
}

// multiCand is a multi-candidate row's own contract: the per-case shim/resolver
// config the two engines must be given IDENTICALLY, the verdict each candidate
// must reach on BOTH engines, and the names that must actually have reached the
// wire.
//
// It is a separate struct rather than more fields on diffCase so a single-candidate
// row cannot half-configure a multi-candidate run by leaving a zero value behind.
type multiCand struct {
	// search is the ONE dedicated search domain this row expands against (empty
	// = no search list at all). One domain, not the standard three, so exactly
	// one search-suffixed candidate exists and its length is calibrated, not
	// incidental.
	search string
	// ndots is the row's ndots. It selects WHICH k3sm_candidates site writes the
	// bare name: ndots above the name's dot count puts the search candidates
	// first and the bare name at the TAIL site.
	ndots int
	// want is the verdict both engines must reach, keyed by CANDIDATE NAME. Keyed
	// by name and not by index on purpose: an expansion-ORDER divergence then
	// surfaces as missing/extra keys instead of as two interchangeable verdicts.
	want map[string]wireVerdict
	// queried is the exact list of names, in order, that EACH engine must have
	// put on the wire. This is the assertion verdict-equality cannot make: the
	// stub answers any unknown name with a synthesized NXDOMAIN, so a candidate
	// that was wrongly queried still MISSES.
	queried []string
}

// searchDomains renders multi's single search domain as the Go resolver's
// SearchDomains slice, so both engines are configured from the same field.
func (m multiCand) searchDomains() []string {
	if m.search == "" {
		return nil
	}
	return []string{m.search}
}

func differentialCases(t *testing.T) []diffCase {
	t.Helper()
	// The boundary is read out of the C shim source rather than restated here, so
	// these two cases follow K3SM_DNS_MAX_NAME_LEN if it is ever re-derived.
	// TestShimMaxNameLenMatchesGo (env_test.go) is what binds that constant to the
	// Go encoder; this pair pins the two engines' BEHAVIOUR either side of it.
	maxNameLen := shimDefine(t, "K3SM_DNS_MAX_NAME_LEN")

	// Calibration for the two multi-candidate boundary rows. Both numbers are
	// DERIVED from the shim's own macros, never restated, so they follow a
	// re-derivation of either constant.
	//
	// maxStored is the longest candidate the shim can hold WITHOUT snprintf
	// truncation (K3SM_MAX_NAME counts the NUL). Staying at or below it is
	// load-bearing for a name-keyed comparison: an over-long candidate keeps its
	// slot and the shim traces the bytes it STORED, so a truncated candidate would
	// be traced under a name the Go side never produced and the two maps could not
	// line up. (unencodable_total_gt255 is the pre-existing case that deliberately
	// does overflow the slot, and it is exempted from the name check below.)
	maxStored := shimDefine(t, "K3SM_MAX_NAME") - 1
	const overSearch = "over.invalid"
	// bareUnderBoundary + "." + overSearch is exactly maxStored bytes: over
	// K3SM_DNS_MAX_NAME_LEN (so the SUFFIXED candidate is unencodable on both
	// engines) yet still storable un-truncated. The bare name itself stays under
	// the boundary, so the two candidates of ONE request straddle it.
	bareUnderBoundary := maxStored - 1 - len(overSearch)
	if bareUnderBoundary > maxNameLen || bareUnderBoundary+1+len(overSearch) <= maxNameLen {
		t.Fatalf("search_suffix_over_boundary calibration broke: bare=%d, bare+.+%q=%d, K3SM_DNS_MAX_NAME_LEN=%d — the bare name must be AT OR UNDER the boundary and the suffixed candidate OVER it",
			bareUnderBoundary, overSearch, bareUnderBoundary+1+len(overSearch), maxNameLen)
	}
	bareOK := nameOfLength(t, bareUnderBoundary)
	// bareOver is the boundary + 1 — the smallest over-long bare name, which is
	// also the largest one the candidate slot still stores un-truncated.
	bareOver := nameOfLength(t, maxNameLen+1)
	if maxNameLen+1 > maxStored {
		t.Fatalf("plain_over_boundary calibration broke: a boundary+1 name (%d) no longer fits the untruncated candidate slot (%d)", maxNameLen+1, maxStored)
	}

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
			why: "INPUT-ONLY (no fixture): a name past the presentation-length ceiling cannot be encoded"},
		{name: "unencodable_empty_label", host: "a..b.test.invalid", want: verdictMiss,
			why: "INPUT-ONLY (no fixture): a zero-length label is unencodable — it must never be SKIPPED into a query for the collapsed name"},
		{name: "boundary_max_name", host: nameOfLength(t, maxNameLen), want: verdictMiss, wire: false,
			why: "a name at EXACTLY the shared ceiling is encodable on both engines: it reaches the wire and the stub's NXDOMAIN makes it a definitive miss"},
		{name: "boundary_over_max_name", host: nameOfLength(t, maxNameLen+1), want: verdictMiss,
			why: "INPUT-ONLY (no fixture): one byte past the ceiling is unencodable on both engines"},
		{name: "unencodable_empty_name", host: "", want: verdictMiss,
			why: "INPUT-ONLY (no fixture): the DEGENERATE empty name — the probe is handed \".\", whose trailing dot both expansions strip to \"\". Go's Pack refuses it as non-canonical; the shim must reject it in k3sm_encode_name rather than fall through its never-executed label loop into a BARE ROOT query"},
		{name: "search_suffix_over_boundary", host: bareOK,
			multi: &multiCand{
				search: overSearch,
				ndots:  15, // above the name's dot count: search candidates first, bare name at the TAIL site
				want: map[string]wireVerdict{
					bareOK + "." + overSearch: verdictMiss, // over the boundary: unencodable
					bareOK:                    verdictMiss, // under it: encodable, answered by the stub's NXDOMAIN
				},
				queried: []string{bareOK},
			},
			why: "the two candidates of ONE request straddle the shared length boundary: the search-suffixed one is unencodable and must MISS with zero wire I/O, while the bare one must reach the wire — the search-loop bad[] site's TRUE polarity and the tail site's FALSE polarity in a single row"},
		{name: "plain_over_boundary", host: bareOver,
			multi: &multiCand{
				// No search list: with one, the suffixed candidate would overflow the
				// shim's candidate slot and be traced under truncated bytes the Go
				// side never produces. An empty list is also precisely what routes the
				// bare name to the TAIL site (nsearch == 0, absolute_first false).
				search:  "",
				ndots:   15,
				want:    map[string]wireVerdict{bareOver: verdictMiss},
				queried: nil,
			},
			why: "INPUT-ONLY (no fixture): a bare name one byte past the ceiling makes EVERY candidate bad — the tail/plain bad[] site's TRUE polarity, proven by zero observed queries on both engines"},
		{name: "cluster_named_service", host: "cluster-named-service.default.svc.cluster.local",
			want: verdictHit, wire: true, probeService: "http",
			why: "a NAMED service on a CLUSTER-scoped candidate must still be QUERIED, not deferred (only an EXTERNAL candidate defers — Caveat 3): the shim traces the same HIT the Go reference reaches, and only then refuses the call with EAI_SERVICE"},
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

// probeDeadline bounds one probe run. The verdict trace is printed BEFORE the
// shim falls through to the host resolver, so killing the probe at the deadline
// never costs a verdict — it only cuts short the ambient post-miss lookup, which
// this gate deliberately does not assert on. Without it a single case can cost
// 30s of wall clock: macOS's own resolver stalls for its full timeout on a name
// of exactly 255 presentation bytes (the boundary_over_max_name fixture with its
// trailing dot), while both shorter and longer names are rejected instantly. The
// bound is well above the shim's own worst case (K3SM_DNS_ATTEMPTS attempts of a
// K3SM_DNS_TIMEOUT_SEC UDP exchange plus a TCP refetch).
const probeDeadline = 10 * time.Second

// shimVerdict runs the probe binary with the REAL dylib injected and reads the
// per-candidate verdict out of the shim's K3SM_DNS_DEBUG trace. It returns the
// verdict and the candidate name the shim reported querying. The probe's own exit
// status is deliberately ignored: after a MISS or an external TEMPFAIL the shim
// defers to the host resolver, whose answer is ambient (see the file comment).
func shimVerdict(t *testing.T, dylib, probe string, stub *templateDNS, host string) (wireVerdict, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), probeDeadline)
	defer cancel()
	// The name is passed ABSOLUTE (trailing dot) so the shim's ndots/search
	// expansion yields exactly ONE candidate — hence exactly one trace line, at
	// the same altitude as the single lookupCandidate call on the Go side.
	cmd := exec.CommandContext(ctx, probe, host+".")
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
		t.Fatalf("want exactly 1 shim verdict trace line for %q, got %d — the shim's K3SM_DNS_DEBUG wording drifted from traceRE, the dylib did not load, or the probe was killed at the %s deadline before it traced:\n%s",
			host, len(m), probeDeadline, out)
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

// traceLine is one parsed per-candidate verdict line from the shim's trace.
type traceLine struct {
	cand    string
	verdict wireVerdict
}

// shimTrace runs the probe with the REAL dylib injected under a PER-CASE shim
// env and returns EVERY per-candidate verdict line it printed, in order.
//
// It is a deliberate SIBLING of shimVerdict, not a refactor of it. Giving
// shimVerdict new parameters (a service argv, a search list, an ndots) would
// re-route all 15 pre-existing single-candidate rows through zero-value
// defaults, and a zero-valued ndots is not a no-op — it is ndots 0, which
// inverts the expansion order. The duplicated exec/parse body is the price of
// leaving those rows on byte-identical behaviour; keep the two in step if the
// trace wording moves (traceRE is still the single home of that wording).
func shimTrace(t *testing.T, dylib, probe string, stub *templateDNS, args []string, search string, ndots int) []traceLine {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), probeDeadline)
	defer cancel()
	cmd := exec.CommandContext(ctx, probe, args...)
	cmd.Env = append(os.Environ(),
		EnvDNSServer+"=127.0.0.1",
		EnvDNSPort+"="+strconv.Itoa(stub.port()),
		EnvDNSDomain+"=cluster.local",
		EnvDNSSearch+"="+search,
		EnvDNSNdots+"="+strconv.Itoa(ndots),
		EnvDNSDebug+"=1",
		"DYLD_INSERT_LIBRARIES="+dylib,
	)
	out, _ := cmd.CombinedOutput()
	ms := traceRE.FindAllStringSubmatch(string(out), -1)
	if len(ms) == 0 {
		t.Fatalf("no shim verdict trace line for probe %v (search=%q ndots=%d) — the shim's K3SM_DNS_DEBUG wording drifted from traceRE, the dylib did not load, or the probe was killed at the %s deadline before it traced:\n%s",
			args, search, ndots, probeDeadline, out)
	}
	lines := make([]traceLine, 0, len(ms))
	for _, m := range ms {
		lines = append(lines, traceLine{cand: m[1], verdict: parseTraceVerdict(t, m[3])})
	}
	return lines
}

// parseTraceVerdict maps the trace's verdict word onto the three-way verdict.
func parseTraceVerdict(t *testing.T, verdict string) wireVerdict {
	t.Helper()
	switch verdict {
	case "HIT":
		return verdictHit
	case "miss":
		return verdictMiss
	case "TEMPFAIL":
		return verdictTempFail
	}
	t.Fatalf("unparsed shim verdict %q", verdict)
	return verdictTempFail
}

// shimVerdictService is shimVerdict's sibling for a row that passes a SERVICE
// argv (diffCase.probeService). The name is still passed ABSOLUTE, so exactly
// one candidate — and therefore exactly one trace line — is expected.
func shimVerdictService(t *testing.T, dylib, probe string, stub *templateDNS, host, service string) (wireVerdict, string) {
	t.Helper()
	lines := shimTrace(t, dylib, probe, stub, []string{host + ".", service},
		strings.Join(stdSearch(), " "), 5)
	if len(lines) != 1 {
		t.Fatalf("want exactly 1 shim verdict trace line for %q with service %q, got %d — an absolute name must collapse to one candidate: %v",
			host, service, len(lines), lines)
	}
	return lines[0].verdict, lines[0].cand
}

// shimVerdictFor routes a SINGLE-CANDIDATE row to the right C-side reader: the
// 15 pre-existing rows keep shimVerdict verbatim, and only a row that opts in
// with a service argv takes the sibling.
func shimVerdictFor(t *testing.T, dylib, probe string, stub *templateDNS, c diffCase) (wireVerdict, string) {
	t.Helper()
	if c.probeService == "" {
		return shimVerdict(t, dylib, probe, stub, c.host)
	}
	return shimVerdictService(t, dylib, probe, stub, c.host, c.probeService)
}

// shimVerdictsPerCandidate is the C-side MULTI-CANDIDATE reader: it hands the
// probe the BARE name (no trailing dot) under mc's own search/ndots env, so the
// shim performs a real expansion, and returns every candidate's verdict keyed by
// the CANDIDATE NAME the shim itself reported.
func shimVerdictsPerCandidate(t *testing.T, dylib, probe string, stub *templateDNS, name string, mc multiCand) map[string]wireVerdict {
	t.Helper()
	lines := shimTrace(t, dylib, probe, stub, []string{name}, mc.search, mc.ndots)
	out := make(map[string]wireVerdict, len(lines))
	for _, l := range lines {
		if _, dup := out[l.cand]; dup {
			t.Fatalf("shim traced candidate %q twice; the trace must carry exactly one line per candidate: %v", l.cand, lines)
		}
		out[l.cand] = l.verdict
	}
	return out
}

// goVerdictsPerCandidate is the Go-side MULTI-CANDIDATE reader: it walks the
// reference resolver's OWN expansion for name under mc's config and classifies
// each candidate through lookupCandidate — the same altitude goVerdict reads,
// one entry per candidate.
func goVerdictsPerCandidate(t *testing.T, stub *templateDNS, name string, mc multiCand) map[string]wireVerdict {
	t.Helper()
	cfg := stdConfig()
	cfg.SearchDomains = mc.searchDomains()
	cfg.NDots = int32(mc.ndots)
	r, err := NewResolver(cfg, withDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, network, stub.addr())
	}), WithTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	cands := r.Candidates(name)
	if len(cands) == 0 {
		t.Fatalf("the Go reference resolver produced no candidates for %q", name)
	}
	out := make(map[string]wireVerdict, len(cands))
	for _, fqdn := range cands {
		if _, dup := out[fqdn]; dup {
			t.Fatalf("candidateNames returned %q twice; dedupe regressed", fqdn)
		}
		addrs, err := r.lookupCandidate(context.Background(), fqdn)
		switch {
		case err != nil && errors.Is(err, ErrTempFail):
			out[fqdn] = verdictTempFail
		case err != nil:
			t.Fatalf("lookupCandidate(%q) returned a non-transient hard error: %v", fqdn, err)
		case len(addrs) > 0:
			out[fqdn] = verdictHit
		default:
			out[fqdn] = verdictMiss
		}
	}
	return out
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

	cases := differentialCases(t)
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

			if c.multi != nil {
				runMultiCandidate(t, dylib, probe, goStub, cStub, c)
				return
			}

			goGot := goVerdict(t, goStub, c.host)
			cGot, cand := shimVerdictFor(t, dylib, probe, cStub, c)
			if goGot != cGot {
				t.Fatalf("C<->Go wire-classification drift on %s (%s):\n  Go reference resolver: %v\n  C getaddrinfo shim:    %v",
					c.name, c.why, goGot, cGot)
			}
			if goGot != c.want {
				t.Fatalf("both engines classify %s (%s) as %v, want %v — parity held but the shared verdict is wrong",
					c.name, c.why, goGot, c.want)
			}
			// Both engines must have judged the SAME name. The one exemption is
			// unencodable_total_gt255, and it is a STORAGE fact, not a divergence:
			// the shim's candidate slot is a K3SM_MAX_NAME (256-byte) buffer, which
			// physically cannot hold that case's longer name, so the trace can only
			// report the stored — truncated — bytes. Nothing is queried or
			// classified from them (the walk short-circuits the slot to a definitive
			// miss first, asserted below); only the debug line sees them.
			if c.name != "unencodable_total_gt255" && cand != c.host {
				t.Fatalf("shim traced candidate %q, want %q — the search expansion did not collapse to one candidate", cand, c.host)
			}

			switch c.name {
			case "unencodable_label_gt63", "unencodable_total_gt255",
				"unencodable_empty_label", "unencodable_empty_name",
				"boundary_over_max_name":
				// Both sides reject at encode time, so NEITHER may touch the wire.
				// Go: Message.Pack fails (errSegTooLong on the 64-byte label,
				// errZeroSegLen on the empty one) or dnsmessage refuses the
				// over-long total. C: k3sm_encode_name returns -1, or
				// k3sm_candidates flags the slot over K3SM_DNS_MAX_NAME_LEN and the
				// walk short-circuits it. Each yields a definitive miss with zero
				// I/O — and, for the over-long names, that is what keeps the
				// TRUNCATED bytes in the candidate slot off the wire and out of the
				// suffix classification.
				assertNoQueries(t, "Go reference resolver", goStub)
				assertNoQueries(t, "C getaddrinfo shim", cStub)
			case "boundary_max_name":
				// The other side of the boundary: at EXACTLY the ceiling both
				// engines still encode the name and ask it. Without this, a shim
				// that rejected one byte too eagerly would pass the zero-queries
				// case above while silently refusing legal names in pods.
				assertQueriedOnce(t, "Go reference resolver", goStub, c.host)
				assertQueriedOnce(t, "C getaddrinfo shim", cStub, c.host)
			}
		})
	}
}

// runMultiCandidate is the MULTI-CANDIDATE half of the differential: it drives a
// real ndots/search expansion on both engines under c.multi's config and compares
// their per-candidate verdict MAPS, then the names each actually queried.
//
// Comparing maps rather than a single verdict is what makes this the first
// behavioural exercise of candidate ORDERING: the keys are candidate names, so an
// engine that expanded to a different candidate set fails with missing/extra keys
// naming the offender, not with two equal verdicts that happen to line up.
func runMultiCandidate(t *testing.T, dylib, probe string, goStub, cStub *templateDNS, c diffCase) {
	t.Helper()
	// A multi row must not half-configure itself as a single-candidate row: the
	// fixture fields belong to the other path and would be silently ignored here.
	if c.wire || c.tcpWire || c.wrongID {
		t.Fatalf("multi-candidate row %s must not set the single-candidate fixture fields (wire=%v tcpWire=%v wrongID=%v)", c.name, c.wire, c.tcpWire, c.wrongID)
	}
	mc := *c.multi

	goGot := goVerdictsPerCandidate(t, goStub, c.host, mc)
	cGot := shimVerdictsPerCandidate(t, dylib, probe, cStub, c.host, mc)
	if !reflect.DeepEqual(goGot, cGot) {
		t.Fatalf("C<->Go per-candidate drift on %s (%s):\n  Go reference resolver: %v\n  C getaddrinfo shim:    %v",
			c.name, c.why, goGot, cGot)
	}
	if !reflect.DeepEqual(goGot, mc.want) {
		t.Fatalf("both engines classify %s (%s) as %v, want %v — parity held but the shared per-candidate verdicts are wrong",
			c.name, c.why, goGot, mc.want)
	}
	// Verdict parity alone is vacuous here: the stub synthesizes NXDOMAIN for any
	// unknown name, so a candidate that was WRONGLY put on the wire still misses.
	// The observed query log is the assertion with teeth.
	assertQueriedNames(t, "Go reference resolver", goStub, mc.queried)
	assertQueriedNames(t, "C getaddrinfo shim", cStub, mc.queried)
}

// assertQueriedNames fails unless side asked for exactly want, in order — the
// wire half of a multi-candidate row (an empty want means nothing may be sent).
func assertQueriedNames(t *testing.T, side string, stub *templateDNS, want []string) {
	t.Helper()
	obs := stub.observed()
	got := make([]string, 0, len(obs))
	for _, q := range obs {
		got = append(got, q.name)
	}
	if len(got) != len(want) {
		t.Fatalf("%s sent %d queries, want %d — an unencodable candidate must never reach the wire and an encodable one must:\n  got:  %v\n  want: %v",
			side, len(got), len(want), got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s queried %q at position %d, want %q:\n  got:  %v\n  want: %v", side, got[i], i, want[i], got, want)
		}
	}
}

// assertNoQueries fails when side put anything on the wire.
func assertNoQueries(t *testing.T, side string, stub *templateDNS) {
	t.Helper()
	if obs := stub.observed(); len(obs) != 0 {
		t.Fatalf("%s queried an unencodable name (%v); such a name can never resolve, so it must never reach the wire", side, obs)
	}
}

// assertQueriedOnce fails unless side asked for exactly want, exactly once — the
// positive half of the boundary pin (an encodable name must reach the wire, and
// must reach it VERBATIM, not truncated).
func assertQueriedOnce(t *testing.T, side string, stub *templateDNS, want string) {
	t.Helper()
	obs := stub.observed()
	if len(obs) != 1 {
		t.Fatalf("%s sent %d queries for a boundary-length name, want exactly 1: %v", side, len(obs), obs)
	}
	if obs[0].name != want {
		t.Fatalf("%s queried %q (%d bytes), want %q (%d bytes) — a name at the encodable ceiling must go on the wire verbatim",
			side, obs[0].name, len(obs[0].name), want, len(want))
	}
}
