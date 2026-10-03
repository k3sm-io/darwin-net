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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/tcpseg"
)

// defaultQueryTimeout bounds a single CoreDNS query attempt.
const defaultQueryTimeout = 2 * time.Second

// queryAttempts is how many times one candidate FQDN is queried when the
// attempt fails transiently (timeout, network error, SERVFAIL). It mirrors the
// resolv.conf "attempts" default; a definitive answer (NOERROR/NXDOMAIN) never
// retries. With several nameservers it is the number of passes over the server
// list (attempt loop outer, server loop inner, as glibc does). The C shim
// mirrors this as K3SM_DNS_ATTEMPTS.
const queryAttempts = 2

// errTransport marks a query that failed at the transport level: the dial, the
// send, or the receive (a timeout or an error such as ECONNREFUSED), on UDP or
// on the TCP refetch. With more than one nameserver a server that fails this
// way is dead for the rest of the lookup. A reply that arrived but could not be
// used (SERVFAIL, malformed) is not a transport failure; it only advances to
// the next server. The C shim draws the same line.
var errTransport = errors.New("dns: transport failure")

// EDNSUDPPayloadSize is the EDNS0 (RFC 6891) UDP payload size the resolver
// advertises in an OPT pseudo-RR on every query, telling CoreDNS it may return
// datagrams up to this many bytes before setting the TC (truncated) bit — so a
// modestly large answer set survives on UDP instead of forcing a TCP refetch.
// 1232 is the widely-adopted conservative EDNS size (1280-byte IPv6 minimum MTU
// minus IPv6+UDP headers), chosen to avoid IP fragmentation. It is the SINGLE Go
// source of the value; the C shim holds the unavoidable copy as
// K3SM_EDNS_UDP_SIZE and TestShimEDNSSizeMatchesC binds the two so they cannot
// drift. (k3sm's netserve imports this const separately.)
const EDNSUDPPayloadSize = 1232

// ErrNotFound is returned by Resolver.LookupHost when no candidate name resolved
// to any address (NXDOMAIN/empty across the whole search list). It mirrors the
// "no such host" outcome the getaddrinfo shim reports to the caller.
var ErrNotFound = errors.New("dns: no address found for name")

// ErrTempFail is returned by Resolver.LookupHost when a candidate query kept
// failing transiently (timeout, network error, SERVFAIL) after queryAttempts.
// It is distinct from ErrNotFound: "the resolver did not answer"
// must never be collapsed into "the name does not exist". The C shim mirrors
// this outcome as EAI_AGAIN.
var ErrTempFail = errors.New("dns: cluster resolver temporarily unavailable")

// Resolver turns a hostname into addresses by applying ndots/search expansion
// (the pure candidateNames logic) and querying the config's nameservers: the
// cluster DNS VIP for ClusterFirst, or the pod's own IPv4 nameservers for
// DNSPolicyNone.
// It is the Go reference implementation of the resolution the getaddrinfo DYLD
// shim performs inside a pod; the shim's C code mirrors this algorithm. The
// transport is plain UDP DNS (the codec is golang.org/x/net/dns/dnsmessage), so
// it stays pure Go.
//
// Server walk (mirrors the C shim). With one nameserver a candidate is retried
// queryAttempts times. With several, each attempt walks the servers in order: a
// HIT or a definitive miss (NXDOMAIN/NODATA) from any server ends the candidate,
// a SERVFAIL or malformed reply moves to the next server, and a server that
// fails at the transport level (errTransport) is dead for the rest of the
// LookupHost call, so a lookup costs at most one timeout per server however many
// candidates it expands to.
//
// Exclusive mode (DNSPolicyNone) classifies every candidate as fail-closed, so a
// transient failure is ErrTempFail and never the ErrNotFound a ClusterFirst
// external candidate reports to let its caller fall through to the host.
//
// A Resolver is safe for concurrent use; it holds no mutable state. The server
// addresses are taken from the DNSConfig, so a Resolver is cheap to construct
// per-config.
type Resolver struct {
	cfg netv1.DNSConfig
	// servers are the nameserver addresses ("ip:port") in query order.
	servers []string
	// exclusive is set for DNSPolicyNone: every candidate fails closed.
	exclusive bool
	timeout   time.Duration
	// dial is the UDP and TCP dial seam; tests point it at a stub DNS server. It
	// defaults to tcpseg.Dialer.DialContext, so the TCP refetch toward the DNS VIP
	// (an lo0 alias) has its segment size clamped like every other connection the
	// node opens to a VIP; a UDP socket passes through the clamp untouched.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// onCandidate, when set, is called once for every candidate LookupHost
	// queries (not for one it skips), with that candidate's outcome. It is a test
	// seam that mirrors the shim's per-candidate debug trace line.
	onCandidate func(cand string, addrs []netip.Addr, err error)
}

// Option configures a Resolver.
type Option func(*Resolver)

// WithTimeout sets the per-query timeout (default 2s).
func WithTimeout(d time.Duration) Option {
	return func(r *Resolver) { r.timeout = d }
}

// NewResolver builds a Resolver for cfg. It returns an error if cfg is not usable
// (cfg.Validate fails), or one wrapping ErrNoUsableNameserver for a
// DNSPolicyNone config with no IPv4 nameserver (the same IPv4 subset the shim
// is given). The DNS server port is 53.
func NewResolver(cfg netv1.DNSConfig, opts ...Option) (*Resolver, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("dns resolver config: %w", err)
	}
	servers := cfg.Servers()
	exclusive := cfg.Policy == netv1.DNSPolicyNone
	if exclusive {
		kept, dropped := ipv4Servers(cfg)
		if len(kept) == 0 {
			return nil, fmt.Errorf("dns resolver config: nameservers %v: %w", dropped, ErrNoUsableNameserver)
		}
		servers = kept
	}
	addrs := make([]string, len(servers))
	for i, s := range servers {
		addrs[i] = net.JoinHostPort(s, "53")
	}
	d := &tcpseg.Dialer{}
	r := &Resolver{
		cfg:       cfg.WithDefaults(),
		servers:   addrs,
		exclusive: exclusive,
		timeout:   defaultQueryTimeout,
		dial:      d.DialContext,
	}
	for _, o := range opts {
		o(r)
	}
	return r, nil
}

// Candidates returns the ordered candidate FQDNs LookupHost will try for name,
// exposing the pure ndots/search expansion for inspection and tests.
func (r *Resolver) Candidates(name string) []string {
	return candidateNames(r.cfg, name)
}

// LookupHost resolves name to one or more IP addresses, trying each ndots/search
// candidate in order and returning the addresses from the first candidate that
// resolves. A SHORT name (e.g. "web") is expanded through the search domains
// first, so it resolves as a Service name without the caller qualifying it.
//
// It returns ErrNotFound when every candidate misses definitively. A TRANSIENT
// failure is scoped by whether the candidate is cluster-scoped (see
// isClusterCandidate): a transient on a CLUSTER candidate fails closed with
// ErrTempFail (wrapped) — never collapsed into a wrong answer from a later
// search domain — while a transient on an EXTERNAL candidate (e.g. "github.com")
// yields ErrNotFound so the caller may fall through to the host resolver,
// keeping external DNS alive across a resolver bounce. The walk continues past a
// cluster transient (a later external candidate may still resolve) and reports
// the remembered ErrTempFail only if nothing else resolves. In exclusive mode
// (DNSPolicyNone) every candidate is cluster-scoped in that sense, so any
// transient failure ends as ErrTempFail.
//
// The dead-server memo (see Resolver) lives for exactly one LookupHost call.
func (r *Resolver) LookupHost(ctx context.Context, name string) ([]netip.Addr, error) {
	cands := r.Candidates(name)
	if len(cands) == 0 {
		return nil, fmt.Errorf("dns: empty query name")
	}
	dead := make([]bool, len(r.servers))
	// clusterTempErr records that a CLUSTER-scoped candidate failed transiently.
	// We keep walking past it (a later external candidate may still resolve), and
	// only fail closed with ErrTempFail at the end if nothing else resolves —
	// mirroring the C shim's cluster_tempfail bookkeeping.
	var clusterTempErr error
	for _, fqdn := range cands {
		// Once a cluster-scoped candidate has failed transiently, skip any
		// remaining cluster-scoped candidate: they ask the same unreachable
		// server, and a definitive answer from a LATER search domain would be a
		// wrong answer for the short name (the risk TestLookupHostServfail...
		// guards). Keep walking only to reach a still-pending external candidate.
		if clusterTempErr != nil && r.isClusterCandidate(fqdn) {
			continue
		}
		addrs, err := r.queryCandidate(ctx, fqdn, dead)
		if r.onCandidate != nil {
			r.onCandidate(fqdn, addrs, err)
		}
		if err != nil {
			if !errors.Is(err, ErrTempFail) {
				// A non-transient hard error (should not normally happen —
				// queryCandidate converts query failures to ErrTempFail).
				return nil, fmt.Errorf("dns: lookup %q: %w", name, err)
			}
			if r.isClusterCandidate(fqdn) {
				// Fail closed for cluster names: never let a transient failure
				// slide into a wrong answer from a later search domain or a host
				// fallthrough. Remember it and keep walking.
				clusterTempErr = err
				continue
			}
			// External candidate (dotted, not under the cluster domain) went
			// transient. The cluster resolver is not authoritative for it; a full
			// in-pod stack falls through to the host resolver here. The reference
			// resolver models no host path, so it reports the cluster miss as
			// ErrNotFound and lets the caller fall through — the deliberate
			// fail-closed-for-cluster / fall-through-for-external trade the C shim
			// makes by deferring to the system getaddrinfo.
			return nil, fmt.Errorf("dns: lookup %q: %w", name, ErrNotFound)
		}
		if len(addrs) > 0 {
			return addrs, nil
		}
	}
	if clusterTempErr != nil {
		return nil, fmt.Errorf("dns: lookup %q: %w", name, clusterTempErr)
	}
	return nil, fmt.Errorf("dns: lookup %q: %w", name, ErrNotFound)
}

// isClusterCandidate reports whether a transient failure on fqdn must fail CLOSED
// (ErrTempFail, no fallthrough) rather than be allowed to fall through to the
// host resolver. A candidate is cluster-scoped when it is under the cluster
// domain or a search domain, OR when it is a bare single-label name (never a
// real external FQDN, so a Service short name). Only a dotted candidate that is
// under NO cluster/search domain (e.g. "github.com") is external. It mirrors the
// C shim's k3sm_candidate_fail_closed.
//
// ACKNOWLEDGED CEILING of the trade: the k8s partial forms "svc.ns" /
// "svc.ns.svc" are dotted and under no suffix, so they classify external —
// during a cluster-resolver outage their search-expanded candidates fail
// closed, but the absolute candidate falls through to the host, whose NXDOMAIN
// turns a TRANSIENT outage into a definitive not-found for exactly those
// forms. Suffix-based scoping cannot tell "db.prod" from "github.com"; the
// bare-label and fully-qualified cluster forms keep the ErrTempFail guarantee.
//
// In exclusive mode (DNSPolicyNone) every candidate is fail-closed: there is no
// host resolver to fall through to. An empty ClusterDomain is skipped, so it
// never makes every name look cluster-scoped.
func (r *Resolver) isClusterCandidate(fqdn string) bool {
	if r.exclusive {
		return true
	}
	name := strings.TrimSuffix(fqdn, ".")
	if !strings.Contains(name, ".") {
		return true // bare label: a cluster short name, never external
	}
	domains := append([]string{r.cfg.ClusterDomain}, r.cfg.SearchDomains...)
	for _, d := range domains {
		d = strings.TrimSuffix(d, ".")
		if d == "" {
			continue
		}
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// queryCandidate resolves one FQDN through the server walk (see Resolver),
// reading and updating dead, the per-lookup dead-server memo. With a single
// server the memo is not consulted: the candidate is retried queryAttempts
// times exactly as a one-server resolv.conf would. A nil error with empty addrs
// is a DEFINITIVE miss (NXDOMAIN or NODATA — the server answered, the name has
// nothing); a non-nil error wraps ErrTempFail and means the outcome is unknown.
func (r *Resolver) queryCandidate(ctx context.Context, fqdn string, dead []bool) ([]netip.Addr, error) {
	var lastErr error
	if len(r.servers) == 1 {
		for range queryAttempts {
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("%w: %w", ErrTempFail, err)
			}
			addrs, done, err := r.askServer(ctx, 0, fqdn)
			if done {
				return addrs, nil
			}
			lastErr = err
		}
		return nil, fmt.Errorf("%w after %d attempts: %w", ErrTempFail, queryAttempts, lastErr)
	}
	for range queryAttempts {
		live := false
		for i := range r.servers {
			if dead[i] {
				continue
			}
			live = true
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("%w: %w", ErrTempFail, err)
			}
			addrs, done, err := r.askServer(ctx, i, fqdn)
			if done {
				return addrs, nil
			}
			lastErr = err
			if errors.Is(err, errTransport) {
				dead[i] = true
			}
		}
		if !live {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("every nameserver is unreachable")
	}
	return nil, fmt.Errorf("%w after %d attempts: %w", ErrTempFail, queryAttempts, lastErr)
}

// askServer sends one query for fqdn to server i. done reports a definitive
// outcome (a HIT, or NXDOMAIN/NODATA with no addresses); otherwise err says why
// the outcome is unknown, wrapping errTransport for a transport failure.
func (r *Resolver) askServer(ctx context.Context, i int, fqdn string) (addrs []netip.Addr, done bool, err error) {
	res, err := r.queryA(ctx, i, fqdn)
	if err != nil {
		return nil, false, err
	}
	switch res.rcode {
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
		return res.addrs, true, nil
	default:
		// SERVFAIL and friends are transient upstream trouble; retrying (or
		// asking the next server) is right and treating them as "no such host"
		// is not.
		return nil, false, fmt.Errorf("server returned %v", res.rcode)
	}
}

// aResult is one candidate query's decoded outcome: the rcode distinguishes a
// definitive NXDOMAIN from transient server trouble, which addrs alone cannot.
type aResult struct {
	addrs []netip.Addr
	rcode dnsmessage.RCode
}

// queryA sends a single A-record query for fqdn to server i over UDP, re-fetching
// over TCP when the response has TC set (RFC 1035 §4.2.2 — the answer set did
// not fit a plain-UDP response).
func (r *Resolver) queryA(ctx context.Context, i int, fqdn string) (aResult, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	name, err := dnsmessage.NewName(ensureFQDN(fqdn))
	if err != nil {
		// An unencodable / too-long name can never resolve at CoreDNS: it is a
		// DEFINITIVE miss, not a transient failure. Report it as NXDOMAIN so the
		// candidate walk advances to the next search candidate (and ultimately
		// ends as ErrNotFound), never as ErrTempFail. Mirrors the C shim, which
		// maps an unencodable name to K3SM_DNS_MISS.
		return aResult{rcode: dnsmessage.RCodeNameError}, nil
	}
	// EDNS0 OPT (RFC 6891) advertising our UDP payload size, mirroring the C
	// shim's k3sm_build_query. Without it CoreDNS assumes the classic 512-byte
	// UDP limit and truncates sooner, forcing needless TCP refetches.
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(EDNSUDPPayloadSize, dnsmessage.RCodeSuccess, false); err != nil {
		return aResult{}, fmt.Errorf("set edns0 opt: %w", err)
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               dnsQueryID(fqdn),
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
		Additionals: []dnsmessage.Resource{{
			Header: opt,
			Body:   &dnsmessage.OPTResource{},
		}},
	}
	packed, err := msg.Pack()
	if err != nil {
		// Same synthetic DEFINITIVE miss as the NewName failure above, for the
		// same reason. Pack's only realistic failure here is NAME ENCODING: the
		// header, question and OPT RR are built from constants, so the single
		// variable input is the name — and dnsmessage.NewName bounds only the
		// TOTAL length, so a name whose defect is a single LABEL sails past it
		// and is rejected here instead. An unencodable name can never resolve at
		// CoreDNS, so retrying it is pointless; returning an error would make
		// queryCandidate retry it like a lost datagram and report ErrTempFail,
		// diverging from the C shim, which reaches the same verdict with zero
		// wire I/O.
		//
		// The C shim now mirrors every name-encoding rejection reachable from a
		// real hostname, each pinned by a named test:
		//   - a label of 64+ bytes (errSegTooLong) — shim: k3sm_encode_name
		//     returns -1. TestUnencodableLabelDefinitiveMiss/"label over the
		//     63-byte ceiling" (this side) and the wire differential's
		//     unencodable_label_gt63 (both engines, zero queries).
		//   - a ZERO-LENGTH label, "a..b" (errZeroSegLen) — shim: the same
		//     k3sm_encode_name reject, which used to SKIP the empty label and
		//     query the collapsed name. TestUnencodableLabelDefinitiveMiss/
		//     "zero-length interior label" and the differential's
		//     unencodable_empty_label.
		//   - a TOTAL length past the ceiling (NewName above, or pack's
		//     nonEncodedNameMax) — shim: k3sm_candidates flags the candidate
		//     against K3SM_DNS_MAX_NAME_LEN and the walk short-circuits it to a
		//     miss BEFORE classifying or querying the snprintf-truncated bytes.
		//     env_test.go's TestShimMaxNameLenMatchesGo binds that constant to
		//     this encoder's real ceiling, and the differential pins the
		//     behaviour on both sides of it (boundary_max_name reaches the wire
		//     on both engines, boundary_over_max_name and unencodable_total_gt255
		//     reach it on neither).
		//   - the degenerate EMPTY name (errNonCanonicalName — ensureFQDN cannot
		//     append a dot to "", so Pack refuses the non-canonical name), which
		//     candidateNames produces for the input "." — shim: the explicit
		//     empty-name reject at the top of k3sm_encode_name, whose per-label
		//     loop never runs for "" and which therefore used to emit a BARE ROOT
		//     query instead of a miss. The differential's unencodable_empty_name
		//     pins it on both engines, verdict AND zero queries — the zero-query
		//     half is what that stray root query tripped.
		return aResult{rcode: dnsmessage.RCodeNameError}, nil
	}

	resp, err := r.exchange(ctx, "udp", r.servers[i], packed)
	if err != nil {
		return aResult{}, err
	}
	res, truncated, err := parseAAddrs(resp, msg.Header.ID)
	if err != nil {
		return aResult{}, err
	}
	if truncated {
		resp, err = r.exchange(ctx, "tcp", r.servers[i], packed)
		if err != nil {
			return aResult{}, fmt.Errorf("tcp refetch: %w", err)
		}
		var stillTruncated bool
		res, stillTruncated, err = parseAAddrs(resp, msg.Header.ID)
		if err != nil {
			return aResult{}, fmt.Errorf("tcp refetch: %w", err)
		}
		if stillTruncated {
			// TC still set on the TCP response is malformed — the answer must
			// fit a length-prefixed TCP message. Treat it as a transient error
			// (it lands in the ErrTempFail bucket via queryCandidate), never a
			// definitive result. Mirrors the C shim's TEMPFAIL on TC-over-TCP.
			return aResult{}, fmt.Errorf("tcp refetch: response still truncated")
		}
	}
	return res, nil
}

// exchange performs one DNS message round-trip with server (an "ip:port"): a
// single datagram on "udp", a length-prefixed message on "tcp" (RFC 1035 §4.2.2
// framing). Every error it returns wraps errTransport.
func (r *Resolver) exchange(ctx context.Context, network, server string, packed []byte) ([]byte, error) {
	resp, err := r.roundTrip(ctx, network, server, packed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errTransport, err)
	}
	return resp, nil
}

// roundTrip is exchange without the errTransport wrap.
func (r *Resolver) roundTrip(ctx context.Context, network, server string, packed []byte) ([]byte, error) {
	conn, err := r.dial(ctx, network, server)
	if err != nil {
		return nil, fmt.Errorf("dial %s %s: %w", network, server, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if network == "tcp" {
		framed := make([]byte, 2+len(packed))
		binary.BigEndian.PutUint16(framed, uint16(len(packed)))
		copy(framed[2:], packed)
		if _, err := conn.Write(framed); err != nil {
			return nil, fmt.Errorf("write query: %w", err)
		}
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return nil, fmt.Errorf("read response length: %w", err)
		}
		resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}
		return resp, nil
	}
	if _, err := conn.Write(packed); err != nil {
		return nil, fmt.Errorf("write query: %w", err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return buf[:n], nil
}

// parseAAddrs decodes a DNS response into its A-record addresses, rcode, and
// truncation bit. It verifies the response ID matches the query.
func parseAAddrs(resp []byte, wantID uint16) (aResult, bool, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil {
		return aResult{}, false, fmt.Errorf("parse header: %w", err)
	}
	if hdr.ID != wantID {
		return aResult{}, false, fmt.Errorf("dns: response id %d != query id %d", hdr.ID, wantID)
	}
	if !hdr.Response {
		return aResult{}, false, fmt.Errorf("dns: message is not a response")
	}
	if err := p.SkipAllQuestions(); err != nil {
		return aResult{}, false, fmt.Errorf("skip questions: %w", err)
	}
	res := aResult{rcode: hdr.RCode}
	if hdr.Truncated {
		return res, true, nil
	}
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return aResult{}, false, fmt.Errorf("answer header: %w", err)
		}
		if ah.Type != dnsmessage.TypeA {
			if err := p.SkipAnswer(); err != nil {
				return aResult{}, false, fmt.Errorf("skip answer: %w", err)
			}
			continue
		}
		ar, err := p.AResource()
		if err != nil {
			return aResult{}, false, fmt.Errorf("a resource: %w", err)
		}
		res.addrs = append(res.addrs, netip.AddrFrom4(ar.A))
	}
	return res, false, nil
}

// ensureFQDN appends a trailing dot if missing, as DNS wire names require.
func ensureFQDN(name string) string {
	if len(name) == 0 || name[len(name)-1] == '.' {
		return name
	}
	return name + "."
}

// dnsQueryID derives a stable 16-bit query ID from the name. A real resolver
// randomizes this for spoofing resistance; over a trusted loopback/mesh path to
// CoreDNS a deterministic ID keeps queries reproducible and is sufficient (the
// shim talks only to the cluster VIP). It is non-zero.
func dnsQueryID(name string) uint16 {
	var h uint32 = 2166136261
	for i := 0; i < len(name); i++ {
		h ^= uint32(name[i])
		h *= 16777619
	}
	id := uint16(h)
	if id == 0 {
		id = 1
	}
	return id
}
