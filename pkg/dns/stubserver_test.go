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

// The stub serves real loopback UDP and TCP for the differential and shim
// tests, which reach it the way libc does. They need no privilege; run with:
//
//	CGO_ENABLED=0 go test -tags integration -run 'Differential|Shim' ./pkg/dns/

package dns

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// stubDNS serves a stubZone (stubzone_test.go) on real loopback sockets: one
// port answering both UDP and TCP. It stands in for CoreDNS so the C shim's
// interpose can be tested without an external CoreDNS binary; the zone, the
// fault injection, and the query log are the stubZone's, so the unit tier's
// in-memory fakeDNS and this server answer identically.
type stubDNS struct {
	*stubZone

	conn  *net.UDPConn
	tcpLn net.Listener

	wg   sync.WaitGroup
	done chan struct{}
}

// newStubDNS starts a stub server bound to 127.0.0.1 on an ephemeral port (same
// port UDP and TCP) and returns it; call addr() for the ip:port and close() to
// stop.
func newStubDNS(t *testing.T, zone map[string]netip.Addr) *stubDNS {
	t.Helper()
	conn, tcpLn := bindSamePortPair(t, bindPairAttempts)
	s := &stubDNS{
		stubZone: newStubZone(zone),
		conn:     conn,
		tcpLn:    tcpLn,
		done:     make(chan struct{}),
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

// newBlackholeDNS binds a UDP socket on 127.0.0.1 that never reads or answers,
// and returns its port. A client querying it waits out its full timeout, which
// is what a nameserver that silently drops traffic costs. The socket closes at
// test cleanup.
func newBlackholeDNS(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("bind blackhole DNS: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr).Port
}
