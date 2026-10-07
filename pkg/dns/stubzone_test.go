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
	"net/netip"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// stubZone is the answering half of the test DNS servers: a fixed name->addr
// zone, per-name fault injection, and a log of every query it was asked. It
// opens nothing; stubDNS (stubserver_test.go, integration tier) serves it on
// real loopback sockets and fakeDNS (fakedns_test.go) serves it over in-memory
// conns through the resolver's dial seam, so both tiers answer identically.
// Names are matched case-insensitively with the trailing dot normalized; an
// unknown name gets an empty (NXDOMAIN-like) answer.
type stubZone struct {
	zone map[string]netip.Addr

	// mu guards every field below.
	mu         sync.Mutex
	queries    []string
	tcpQueries []string
	// log is every query in arrival order, with its transport and message ID.
	log []stubQuery
	// Fault injection, keyed by normalized name: drop swallows the next N UDP
	// queries for the name (no response — the client times out); servfail
	// answers with RCodeServerFailure; truncate answers UDP with TC set and no
	// answers; truncateTCP answers even the TCP refetch with TC set and no
	// answers (a malformed server, to exercise the TC-over-TCP transient path).
	drop        map[string]int
	servfail    map[string]bool
	truncate    map[string]bool
	truncateTCP map[string]bool
	// silent makes the stub record every query and answer none of them: a server
	// that is reachable but dead, whose queries can still be counted.
	silent bool
	// EDNS0 OPT observed on the most recent query (any transport): optSeen is set
	// when the query carried an OPT pseudo-RR, and optUDPSize is its advertised
	// UDP payload size (the OPT ResourceHeader Class field).
	optSeen    bool
	optUDPSize int
}

// stubQuery is one query a stubZone received.
type stubQuery struct {
	transport string // "udp" or "tcp"
	name      string // normalized
	id        uint16
	qtype     dnsmessage.Type
}

// newStubZone returns a zone answering A queries from zone.
func newStubZone(zone map[string]netip.Addr) *stubZone {
	return &stubZone{
		zone:        zone,
		drop:        map[string]int{},
		servfail:    map[string]bool{},
		truncate:    map[string]bool{},
		truncateTCP: map[string]bool{},
	}
}

// dropNext makes the stub swallow the next n UDP queries for name.
func (s *stubZone) dropNext(name string, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drop[normalizeName(name)] = n
}

// setSilent makes the stub record every query and never answer: the client
// times out against it, and queryCount still sees each query.
func (s *stubZone) setSilent() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.silent = true
}

// queryCount returns how many queries (UDP and TCP) the stub has received.
func (s *stubZone) queryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queries) + len(s.tcpQueries)
}

// setServfail makes every query for name answer SERVFAIL.
func (s *stubZone) setServfail(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.servfail[normalizeName(name)] = true
}

// setTruncateUDP makes UDP queries for name answer with TC set and no answers;
// the TCP listener still serves the zone answer.
func (s *stubZone) setTruncateUDP(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.truncate[normalizeName(name)] = true
}

// setTruncateTCP makes even the TCP refetch for name answer with TC set and no
// answers — a malformed server, used to exercise the TC-over-TCP transient path.
func (s *stubZone) setTruncateTCP(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.truncateTCP[normalizeName(name)] = true
}

// lastOPT returns whether the most recent query carried an EDNS0 OPT record and
// the UDP payload size it advertised.
func (s *stubZone) lastOPT() (seen bool, udpSize int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.optSeen, s.optUDPSize
}

// askedTCP reports whether the server received a TCP query for the given name.
func (s *stubZone) askedTCP(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := normalizeName(name)
	for _, q := range s.tcpQueries {
		if q == want {
			return true
		}
	}
	return false
}

// asked reports whether the server received a query for the given name (trailing
// dot optional).
func (s *stubZone) asked(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := normalizeName(name)
	for _, q := range s.queries {
		if q == want {
			return true
		}
	}
	return false
}

// queriesFor returns every query received for name (trailing dot optional), in
// arrival order.
func (s *stubZone) queriesFor(name string) []stubQuery {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := normalizeName(name)
	var out []stubQuery
	for _, q := range s.log {
		if q.name == want {
			out = append(out, q)
		}
	}
	return out
}

// respond decodes a query and builds an A response from the zone, honoring the
// per-name fault injection for the given transport.
func (s *stubZone) respond(query []byte, transport string) ([]byte, bool) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil, false
	}
	q, err := p.Question()
	if err != nil {
		return nil, false
	}
	qname := normalizeName(q.Name.String())

	// Record whether the query carried an EDNS0 OPT pseudo-RR and its advertised
	// UDP payload size. A full Unpack is simplest here (the streaming parser above
	// only read the question); the OPT lives in the Additional section.
	optSeen, optSize := false, 0
	var full dnsmessage.Message
	if err := full.Unpack(query); err == nil {
		for _, a := range full.Additionals {
			if a.Header.Type == dnsmessage.TypeOPT {
				optSeen = true
				optSize = int(a.Header.Class)
			}
		}
	}

	s.mu.Lock()
	s.optSeen = optSeen
	s.optUDPSize = optSize
	s.log = append(s.log, stubQuery{transport: transport, name: qname, id: hdr.ID, qtype: q.Type})
	if transport == "tcp" {
		s.tcpQueries = append(s.tcpQueries, qname)
	} else {
		s.queries = append(s.queries, qname)
	}
	if s.silent {
		s.mu.Unlock()
		return nil, false
	}
	if transport == "udp" && s.drop[qname] > 0 {
		s.drop[qname]--
		s.mu.Unlock()
		return nil, false
	}
	fail := s.servfail[qname]
	trunc := (transport == "udp" && s.truncate[qname]) ||
		(transport == "tcp" && s.truncateTCP[qname])
	s.mu.Unlock()

	rb := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:            hdr.ID,
		Response:      true,
		Authoritative: true,
		Truncated:     trunc,
	})
	if fail {
		rb = dnsmessage.NewBuilder(nil, dnsmessage.Header{
			ID:       hdr.ID,
			Response: true,
			RCode:    dnsmessage.RCodeServerFailure,
		})
	}
	if err := rb.StartQuestions(); err != nil {
		return nil, false
	}
	if err := rb.Question(q); err != nil {
		return nil, false
	}
	addr, found := s.zone[qname]
	if found && q.Type == dnsmessage.TypeA && !fail && !trunc {
		if err := rb.StartAnswers(); err != nil {
			return nil, false
		}
		ah := dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}
		if err := rb.AResource(ah, dnsmessage.AResource{A: addr.As4()}); err != nil {
			return nil, false
		}
	}
	out, err := rb.Finish()
	if err != nil {
		return nil, false
	}
	return out, true
}

// normalizeName lowercases a DNS name and strips a single trailing dot.
func normalizeName(n string) string {
	if len(n) > 0 && n[len(n)-1] == '.' {
		n = n[:len(n)-1]
	}
	return toLowerASCII(n)
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
