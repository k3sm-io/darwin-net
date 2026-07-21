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
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// stubDNS is a minimal in-process UDP DNS server answering A queries from a fixed
// name->addr zone. It stands in for CoreDNS so the resolver's wire path and (in
// the integration tier) the C shim's interpose can be tested without an external
// CoreDNS binary. Names are matched case-insensitively with the trailing dot
// normalized; an unknown name gets an empty (NXDOMAIN-like) answer.
type stubDNS struct {
	conn  *net.UDPConn
	tcpLn net.Listener
	zone  map[string]netip.Addr

	mu         sync.Mutex
	queries    []string
	tcpQueries []string
	// Fault injection, keyed by normalized name: drop swallows the next N UDP
	// queries for the name (no response — the client times out); servfail
	// answers with RCodeServerFailure; truncate answers UDP with TC set and no
	// answers; truncateTCP answers even the TCP refetch with TC set and no
	// answers (a malformed server, to exercise the TC-over-TCP transient path).
	drop        map[string]int
	servfail    map[string]bool
	truncate    map[string]bool
	truncateTCP map[string]bool
	// EDNS0 OPT observed on the most recent query (any transport): optSeen is set
	// when the query carried an OPT pseudo-RR, and optUDPSize is its advertised
	// UDP payload size (the OPT ResourceHeader Class field).
	optSeen    bool
	optUDPSize int

	wg   sync.WaitGroup
	done chan struct{}
}

// newStubDNS starts a stub server bound to 127.0.0.1 on an ephemeral port (same
// port UDP and TCP) and returns it; call addr() for the ip:port and close() to
// stop.
func newStubDNS(t *testing.T, zone map[string]netip.Addr) *stubDNS {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("stub dns listen: %v", err)
	}
	tcpLn, err := net.Listen("tcp", conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("stub dns tcp listen: %v", err)
	}
	s := &stubDNS{
		conn:        conn,
		tcpLn:       tcpLn,
		zone:        zone,
		drop:        map[string]int{},
		servfail:    map[string]bool{},
		truncate:    map[string]bool{},
		truncateTCP: map[string]bool{},
		done:        make(chan struct{}),
	}
	s.wg.Add(2)
	go s.serve()
	go s.serveTCP()
	return s
}

func (s *stubDNS) addr() string { return s.conn.LocalAddr().String() }

func (s *stubDNS) port() int { return s.conn.LocalAddr().(*net.UDPAddr).Port }

func (s *stubDNS) close() {
	close(s.done)
	_ = s.conn.Close()
	_ = s.tcpLn.Close()
	s.wg.Wait()
}

// dropNext makes the stub swallow the next n UDP queries for name.
func (s *stubDNS) dropNext(name string, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drop[normalizeName(name)] = n
}

// setServfail makes every query for name answer SERVFAIL.
func (s *stubDNS) setServfail(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.servfail[normalizeName(name)] = true
}

// setTruncateUDP makes UDP queries for name answer with TC set and no answers;
// the TCP listener still serves the zone answer.
func (s *stubDNS) setTruncateUDP(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.truncate[normalizeName(name)] = true
}

// setTruncateTCP makes even the TCP refetch for name answer with TC set and no
// answers — a malformed server, used to exercise the TC-over-TCP transient path.
func (s *stubDNS) setTruncateTCP(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.truncateTCP[normalizeName(name)] = true
}

// lastOPT returns whether the most recent query carried an EDNS0 OPT record and
// the UDP payload size it advertised.
func (s *stubDNS) lastOPT() (seen bool, udpSize int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.optSeen, s.optUDPSize
}

// askedTCP reports whether the server received a TCP query for the given name.
func (s *stubDNS) askedTCP(name string) bool {
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
func (s *stubDNS) asked(name string) bool {
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

func (s *stubDNS) serve() {
	defer s.wg.Done()
	buf := make([]byte, 1500)
	for {
		select {
		case <-s.done:
			return
		default:
		}
		_ = s.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, raddr, err := s.conn.ReadFromUDP(buf)
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
		_, _ = s.conn.WriteToUDP(resp, raddr)
	}
}

// serveTCP answers length-prefixed DNS-over-TCP queries, one message per
// connection, always from the real zone (no truncation/drop on TCP).
func (s *stubDNS) serveTCP() {
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

// respond decodes a query and builds an A response from the zone, honoring the
// per-name fault injection for the given transport.
func (s *stubDNS) respond(query []byte, transport string) ([]byte, bool) {
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
	if transport == "tcp" {
		s.tcpQueries = append(s.tcpQueries, qname)
	} else {
		s.queries = append(s.queries, qname)
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
