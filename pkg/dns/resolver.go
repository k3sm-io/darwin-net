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
)

// defaultQueryTimeout bounds a single CoreDNS query attempt.
const defaultQueryTimeout = 2 * time.Second

// queryAttempts is how many times one candidate FQDN is queried when the
// attempt fails transiently (timeout, network error, SERVFAIL). It mirrors the
// resolv.conf "attempts" default; a definitive answer (NOERROR/NXDOMAIN) never
// retries. The C shim mirrors this as K3SM_DNS_ATTEMPTS.
const queryAttempts = 2

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
// It is deliberately distinct from ErrNotFound: "the resolver did not answer"
// must never be collapsed into "the name does not exist". The C shim mirrors
// this outcome as EAI_AGAIN.
var ErrTempFail = errors.New("dns: cluster resolver temporarily unavailable")

// Resolver turns a hostname into addresses by applying ndots/search expansion
// (the pure candidateNames logic) and querying CoreDNS over the cluster DNS VIP.
// It is the Go reference implementation of the resolution the getaddrinfo DYLD
// shim performs inside a pod; the shim's C code mirrors this algorithm. The
// transport is plain UDP DNS (the codec is golang.org/x/net/dns/dnsmessage), so
// it stays pure Go.
//
// A Resolver is safe for concurrent use; it holds no mutable state. The cluster
// DNS server address is taken from the DNSConfig, so a Resolver is cheap to
// construct per-config.
type Resolver struct {
	cfg     netv1.DNSConfig
	timeout time.Duration
	// dial is the UDP dial seam; tests point it at a stub DNS server. It defaults
	// to net.Dialer.DialContext.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Option configures a Resolver.
type Option func(*Resolver)

// WithTimeout sets the per-query timeout (default 2s).
func WithTimeout(d time.Duration) Option {
	return func(r *Resolver) { r.timeout = d }
}

// withDialer overrides the UDP dialer; tests use it to reach a stub server.
func withDialer(d func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(r *Resolver) { r.dial = d }
}

// NewResolver builds a Resolver for cfg. It returns an error if cfg is not usable
// (missing cluster DNS IP or domain). The DNS server port defaults to 53.
func NewResolver(cfg netv1.DNSConfig, opts ...Option) (*Resolver, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("dns resolver config: %w", err)
	}
	d := &net.Dialer{}
	r := &Resolver{
		cfg:     cfg.WithDefaults(),
		timeout: defaultQueryTimeout,
		dial:    d.DialContext,
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

// serverAddr returns the cluster DNS server's ip:port (port 53).
func (r *Resolver) serverAddr() string {
	return net.JoinHostPort(r.cfg.ClusterDNSIP, "53")
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
// the remembered ErrTempFail only if nothing else resolves.
func (r *Resolver) LookupHost(ctx context.Context, name string) ([]netip.Addr, error) {
	cands := r.Candidates(name)
	if len(cands) == 0 {
		return nil, fmt.Errorf("dns: empty query name")
	}
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
		addrs, err := r.lookupCandidate(ctx, fqdn)
		if err != nil {
			if !errors.Is(err, ErrTempFail) {
				// A non-transient hard error (should not normally happen —
				// lookupCandidate converts query failures to ErrTempFail).
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
func (r *Resolver) isClusterCandidate(fqdn string) bool {
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

// lookupCandidate resolves one FQDN, retrying transient failures up to
// queryAttempts. A nil error with empty addrs is a DEFINITIVE miss (NXDOMAIN or
// NODATA — the server answered, the name has nothing); a non-nil error wraps
// ErrTempFail and means the outcome is unknown.
func (r *Resolver) lookupCandidate(ctx context.Context, fqdn string) ([]netip.Addr, error) {
	var lastErr error
	for range queryAttempts {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTempFail, err)
		}
		res, err := r.queryA(ctx, fqdn)
		if err != nil {
			lastErr = err
			continue
		}
		switch res.rcode {
		case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
			return res.addrs, nil
		default:
			// SERVFAIL and friends are transient upstream trouble; retrying is
			// right and treating them as "no such host" is not.
			lastErr = fmt.Errorf("server returned %v", res.rcode)
		}
	}
	return nil, fmt.Errorf("%w after %d attempts: %v", ErrTempFail, queryAttempts, lastErr)
}

// aResult is one candidate query's decoded outcome: the rcode distinguishes a
// definitive NXDOMAIN from transient server trouble, which addrs alone cannot.
type aResult struct {
	addrs []netip.Addr
	rcode dnsmessage.RCode
}

// queryA sends a single A-record query for fqdn to CoreDNS over UDP, re-fetching
// over TCP when the response has TC set (RFC 1035 §4.2.2 — the answer set did
// not fit a plain-UDP response).
func (r *Resolver) queryA(ctx context.Context, fqdn string) (aResult, error) {
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
		return aResult{}, fmt.Errorf("pack query: %w", err)
	}

	resp, err := r.exchange(ctx, "udp", packed)
	if err != nil {
		return aResult{}, err
	}
	res, truncated, err := parseAAddrs(resp, msg.Header.ID)
	if err != nil {
		return aResult{}, err
	}
	if truncated {
		resp, err = r.exchange(ctx, "tcp", packed)
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
			// (it lands in the ErrTempFail bucket via lookupCandidate), never a
			// definitive result. Mirrors the C shim's TEMPFAIL on TC-over-TCP.
			return aResult{}, fmt.Errorf("tcp refetch: response still truncated")
		}
	}
	return res, nil
}

// exchange performs one DNS message round-trip: a single datagram on "udp", a
// length-prefixed message on "tcp" (RFC 1035 §4.2.2 framing).
func (r *Resolver) exchange(ctx context.Context, network string, packed []byte) ([]byte, error) {
	conn, err := r.dial(ctx, network, r.serverAddr())
	if err != nil {
		return nil, fmt.Errorf("dial coredns %s %s: %w", network, r.serverAddr(), err)
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
