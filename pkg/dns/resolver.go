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
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	netv1 "k3sm.io/apis/net/v1"
)

// defaultQueryTimeout bounds a single CoreDNS query attempt.
const defaultQueryTimeout = 2 * time.Second

// ErrNotFound is returned by Resolver.LookupHost when no candidate name resolved
// to any address (NXDOMAIN/empty across the whole search list). It mirrors the
// "no such host" outcome the getaddrinfo shim reports to the caller.
var ErrNotFound = errors.New("dns: no address found for name")

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
// first, so it resolves as a Service name without the caller qualifying it. It
// returns ErrNotFound when no candidate resolves.
func (r *Resolver) LookupHost(ctx context.Context, name string) ([]netip.Addr, error) {
	cands := r.Candidates(name)
	if len(cands) == 0 {
		return nil, fmt.Errorf("dns: empty query name")
	}
	var firstErr error
	for _, fqdn := range cands {
		addrs, err := r.queryA(ctx, fqdn)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if len(addrs) > 0 {
			return addrs, nil
		}
	}
	if firstErr != nil {
		return nil, fmt.Errorf("dns: lookup %q: %w", name, firstErr)
	}
	return nil, fmt.Errorf("dns: lookup %q: %w", name, ErrNotFound)
}

// queryA sends a single A-record query for fqdn to CoreDNS and returns the
// answer addresses (empty when the name has no A records / NXDOMAIN).
func (r *Resolver) queryA(ctx context.Context, fqdn string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	name, err := dnsmessage.NewName(ensureFQDN(fqdn))
	if err != nil {
		return nil, fmt.Errorf("encode name %q: %w", fqdn, err)
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
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack query: %w", err)
	}

	conn, err := r.dial(ctx, "udp", r.serverAddr())
	if err != nil {
		return nil, fmt.Errorf("dial coredns %s: %w", r.serverAddr(), err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(packed); err != nil {
		return nil, fmt.Errorf("write query: %w", err)
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return parseAAddrs(buf[:n], msg.Header.ID)
}

// parseAAddrs decodes a DNS response and returns its A-record addresses. It
// verifies the response ID matches the query.
func parseAAddrs(resp []byte, wantID uint16) ([]netip.Addr, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}
	if hdr.ID != wantID {
		return nil, fmt.Errorf("dns: response id %d != query id %d", hdr.ID, wantID)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, fmt.Errorf("skip questions: %w", err)
	}
	var addrs []netip.Addr
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("answer header: %w", err)
		}
		if ah.Type != dnsmessage.TypeA {
			if err := p.SkipAnswer(); err != nil {
				return nil, fmt.Errorf("skip answer: %w", err)
			}
			continue
		}
		ar, err := p.AResource()
		if err != nil {
			return nil, fmt.Errorf("a resource: %w", err)
		}
		addrs = append(addrs, netip.AddrFrom4(ar.A))
	}
	return addrs, nil
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
