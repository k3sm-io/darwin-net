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
	conn *net.UDPConn
	zone map[string]netip.Addr

	mu      sync.Mutex
	queries []string

	wg   sync.WaitGroup
	done chan struct{}
}

// newStubDNS starts a stub server bound to 127.0.0.1 on an ephemeral port and
// returns it; call addr() for the ip:port and close() to stop.
func newStubDNS(t *testing.T, zone map[string]netip.Addr) *stubDNS {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("stub dns listen: %v", err)
	}
	s := &stubDNS{conn: conn, zone: zone, done: make(chan struct{})}
	s.wg.Add(1)
	go s.serve()
	return s
}

func (s *stubDNS) addr() string { return s.conn.LocalAddr().String() }

func (s *stubDNS) port() int { return s.conn.LocalAddr().(*net.UDPAddr).Port }

func (s *stubDNS) close() {
	close(s.done)
	_ = s.conn.Close()
	s.wg.Wait()
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
		resp, ok := s.respond(buf[:n])
		if !ok {
			continue
		}
		_, _ = s.conn.WriteToUDP(resp, raddr)
	}
}

// respond decodes a query and builds an A response from the zone.
func (s *stubDNS) respond(query []byte) ([]byte, bool) {
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

	s.mu.Lock()
	s.queries = append(s.queries, qname)
	s.mu.Unlock()

	rb := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:            hdr.ID,
		Response:      true,
		Authoritative: true,
	})
	if err := rb.StartQuestions(); err != nil {
		return nil, false
	}
	if err := rb.Question(q); err != nil {
		return nil, false
	}
	addr, found := s.zone[qname]
	if found && q.Type == dnsmessage.TypeA {
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
