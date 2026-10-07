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
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// fakeDNS serves a stubZone over in-memory conns through the resolver's dial
// seam, so the unit tier exercises the resolver's whole wire path (packing, the
// EDNS0 OPT, the retry and server walk, the TC→TCP refetch, response parsing)
// without a socket. Its conns keep the two transports' framing honest: a UDP
// conn delivers one whole DNS message per Read, a TCP conn is a byte stream
// carrying 2-byte length-prefixed messages (RFC 1035 §4.2.2), and a query the
// zone does not answer (dropped, or a silent server) leaves the Read waiting
// until the conn's deadline expires with an i/o timeout, as a real one would.
type fakeDNS struct {
	*stubZone

	// ap is the server's "ip:port", the address the resolver dials.
	ap netip.AddrPort
	// dials counts every conn the resolver opened to this server.
	dials atomic.Int64
}

// newFakeDNS returns a fake server at ap answering from zone.
func newFakeDNS(ap string, zone map[string]netip.Addr) *fakeDNS {
	return &fakeDNS{stubZone: newStubZone(zone), ap: netip.MustParseAddrPort(ap)}
}

func (f *fakeDNS) addr() string { return f.ap.String() }

// dialFakes returns an Option pointing the resolver's dial seam at the fake
// servers. With one server every dial reaches it, whatever address the config
// names (the fake analog of redirecting a realistic VIP to a stub); with
// several, a dial reaches the server whose addr it names, and any other address
// is refused.
func dialFakes(servers ...*fakeDNS) Option {
	return withDialer(func(_ context.Context, network, addr string) (net.Conn, error) {
		var f *fakeDNS
		if len(servers) == 1 {
			f = servers[0]
		}
		for _, s := range servers {
			if len(servers) > 1 && s.addr() == addr {
				f = s
			}
		}
		if f == nil {
			return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
		}
		f.dials.Add(1)
		return newFakeDNSConn(f.stubZone, network, f.ap), nil
	})
}

// fakeDNSConn is one in-memory client conn to a stubZone.
type fakeDNSConn struct {
	zone    *stubZone
	network string // "udp" or "tcp"
	local   net.Addr
	remote  net.Addr
	closed  chan struct{}
	once    sync.Once

	// mu guards every field below.
	mu       sync.Mutex
	deadline time.Time
	msgs     [][]byte // udp: whole response datagrams, oldest first
	stream   []byte   // tcp: response bytes not yet read
	pending  []byte   // tcp: query bytes not yet framed into a whole message
}

func newFakeDNSConn(zone *stubZone, network string, server netip.AddrPort) *fakeDNSConn {
	c := &fakeDNSConn{zone: zone, network: network, closed: make(chan struct{})}
	client := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 53000)
	if network == "tcp" {
		c.local, c.remote = net.TCPAddrFromAddrPort(client), net.TCPAddrFromAddrPort(server)
	} else {
		c.local, c.remote = net.UDPAddrFromAddrPort(client), net.UDPAddrFromAddrPort(server)
	}
	return c
}

// Write hands the query to the zone. On udp p is one whole query datagram; on
// tcp p is stream bytes, answered once a whole length-prefixed message is in.
func (c *fakeDNSConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, c.opErr("write", net.ErrClosed)
	default:
	}
	if c.network != "tcp" {
		if resp, ok := c.zone.respond(p, "udp"); ok {
			c.mu.Lock()
			c.msgs = append(c.msgs, resp)
			c.mu.Unlock()
		}
		return len(p), nil
	}
	c.mu.Lock()
	c.pending = append(c.pending, p...)
	var queries [][]byte
	for len(c.pending) >= 2 {
		n := int(binary.BigEndian.Uint16(c.pending))
		if len(c.pending) < 2+n {
			break
		}
		queries = append(queries, append([]byte(nil), c.pending[2:2+n]...))
		c.pending = c.pending[2+n:]
	}
	c.mu.Unlock()
	for _, q := range queries {
		resp, ok := c.zone.respond(q, "tcp")
		if !ok {
			continue
		}
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
		c.mu.Lock()
		c.stream = append(c.stream, append(framed, resp...)...)
		c.mu.Unlock()
	}
	return len(p), nil
}

// Read returns the next response: one whole datagram on udp (truncated to p,
// as a datagram read is), the next stream bytes on tcp. With nothing to read it
// waits for the deadline (an i/o timeout) or Close: every response is produced
// synchronously by Write, so nothing else can arrive.
func (c *fakeDNSConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	switch {
	case c.network != "tcp" && len(c.msgs) > 0:
		n := copy(p, c.msgs[0])
		c.msgs = c.msgs[1:]
		c.mu.Unlock()
		return n, nil
	case c.network == "tcp" && len(c.stream) > 0:
		n := copy(p, c.stream)
		c.stream = c.stream[n:]
		c.mu.Unlock()
		return n, nil
	}
	dl := c.deadline
	c.mu.Unlock()

	var expired <-chan time.Time
	if !dl.IsZero() {
		timer := time.NewTimer(time.Until(dl))
		defer timer.Stop()
		expired = timer.C
	}
	select {
	case <-expired:
		return 0, c.opErr("read", os.ErrDeadlineExceeded)
	case <-c.closed:
		return 0, c.opErr("read", net.ErrClosed)
	}
}

func (c *fakeDNSConn) opErr(op string, err error) error {
	return &net.OpError{Op: op, Net: c.network, Source: c.local, Addr: c.remote, Err: err}
}

func (c *fakeDNSConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeDNSConn) LocalAddr() net.Addr  { return c.local }
func (c *fakeDNSConn) RemoteAddr() net.Addr { return c.remote }

func (c *fakeDNSConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	return nil
}

func (c *fakeDNSConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *fakeDNSConn) SetWriteDeadline(t time.Time) error { return nil }
