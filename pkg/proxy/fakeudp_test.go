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

package proxy

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// This file holds the in-memory datagram fakes the UDP relay's unit tests run on,
// so those tests open no socket. The contract every fake here keeps, and that
// TestFakeUDPContract pins:
//
//   - A read blocks until a datagram is available or the fake is closed. It never
//     polls and never returns a zero-length "nothing yet".
//   - Close closes a done channel exactly once (it is idempotent), which unblocks
//     every blocked reader; every later read or write returns net.ErrClosed.
//   - Writes, reads, and Close are safe to call concurrently from any goroutine.
//   - A write that finds its queue full drops the datagram and still succeeds,
//     which is what a UDP socket does with a full receive buffer.
//
// fakeVIPConn adds one more promise: a "datagram handled" barrier. deliver hands
// a datagram to the reader and returns only when that reader comes back for the
// next one. The relay's dispatcher is that single reader, and between two reads it
// resolves the flow and writes upstream, so deliver returning means the datagram
// was fully dispatched. Tests synchronise on that instead of sleeping.

// fakeQueueDepth bounds every fake datagram queue. It is far above what any unit
// test keeps in flight; past it a write drops, like a full socket buffer.
const fakeQueueDepth = 1024

// fakeHandledTimeout is the liveness backstop for the barrier and for reply waits:
// a correct relay answers in microseconds, so hitting it means a hang, not load.
const fakeHandledTimeout = 30 * time.Second

// fakeDatagram is one queued datagram and the address it is from (reads) or to
// (writes).
type fakeDatagram struct {
	data []byte
	addr netip.AddrPort
}

// fakeVIPConn is an in-memory udpVIPConn: the test plays the clients, delivering
// datagrams and reading the relay's replies.
//
// Locking discipline: in, out, handled, and done are channels and need no lock.
// pending is touched only by the single reading goroutine (the relay's
// dispatcher); deliver never reads it, it only waits on handled.
type fakeVIPConn struct {
	local   netip.AddrPort
	in      chan fakeDatagram // client → VIP, consumed by ReadFromUDPAddrPort
	out     chan fakeDatagram // VIP → client, filled by WriteToUDPAddrPort
	handled chan struct{}     // one token per datagram the reader came back from
	done    chan struct{}
	once    sync.Once
	pending bool // a datagram was returned and its handled token is owed (reader-only)
}

// newFakeVIPConn returns an open fake VIP socket that reports local as its
// address.
func newFakeVIPConn(local netip.AddrPort) *fakeVIPConn {
	return &fakeVIPConn{
		local:   local,
		in:      make(chan fakeDatagram, fakeQueueDepth),
		out:     make(chan fakeDatagram, fakeQueueDepth),
		handled: make(chan struct{}, fakeQueueDepth),
		done:    make(chan struct{}),
	}
}

// ReadFromUDPAddrPort blocks until a client datagram is delivered or the conn is
// closed. Entering it settles the previous datagram's handled token.
func (c *fakeVIPConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	if c.pending {
		c.pending = false
		c.handled <- struct{}{}
	}
	select {
	case <-c.done:
		return 0, netip.AddrPort{}, net.ErrClosed
	default:
	}
	select {
	case <-c.done:
		return 0, netip.AddrPort{}, net.ErrClosed
	case d := <-c.in:
		c.pending = true
		return copy(b, d.data), d.addr, nil
	}
}

// WriteToUDPAddrPort queues a reply to addr for the test to read.
func (c *fakeVIPConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	select {
	case c.out <- fakeDatagram{data: append([]byte(nil), b...), addr: addr}:
	default: // full: dropped, as a socket buffer would
	}
	return len(b), nil
}

// LocalAddr reports the fake's bound address.
func (c *fakeVIPConn) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(c.local) }

// Close closes the conn once; later calls are no-ops that return nil.
func (c *fakeVIPConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}

// closed reports whether Close has been called.
func (c *fakeVIPConn) closed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// deliver hands payload from client to the reader and waits until the reader has
// handled it (come back for the next datagram).
func (c *fakeVIPConn) deliver(t *testing.T, client netip.AddrPort, payload string) {
	t.Helper()
	select {
	case c.in <- fakeDatagram{data: []byte(payload), addr: client}:
	case <-time.After(fakeHandledTimeout):
		t.Fatalf("fake VIP: delivering %q from %v blocked", payload, client)
	}
	select {
	case <-c.handled:
	case <-time.After(fakeHandledTimeout):
		t.Fatalf("fake VIP: datagram %q from %v was never handled", payload, client)
	}
}

// reply returns the next datagram the relay wrote back to a client.
func (c *fakeVIPConn) reply(t *testing.T) fakeDatagram {
	t.Helper()
	select {
	case d := <-c.out:
		return d
	case <-time.After(fakeHandledTimeout):
		t.Fatalf("fake VIP: no reply within %v", fakeHandledTimeout)
		return fakeDatagram{}
	}
}

// fakeUpstream is an in-memory udpUpstream: one connected per-flow socket to a
// fakeUDPBackend. With echo set, every datagram written is queued back for Read.
//
// Locking discipline: writes is guarded by mu; rx and done are channels.
type fakeUpstream struct {
	local  netip.AddrPort
	remote netip.AddrPort
	// laddr is the source address the relay asked the dial to bind (nil for
	// kernel default source selection), recorded as passed.
	laddr *net.UDPAddr
	echo  bool
	rx    chan []byte
	done  chan struct{}
	once  sync.Once

	mu     sync.Mutex
	writes int
}

// Read blocks until an echoed datagram is queued or the upstream is closed.
func (u *fakeUpstream) Read(b []byte) (int, error) {
	select {
	case <-u.done:
		return 0, net.ErrClosed
	default:
	}
	select {
	case <-u.done:
		return 0, net.ErrClosed
	case d := <-u.rx:
		return copy(b, d), nil
	}
}

// Write records the datagram and, with echo set, queues it back for Read.
func (u *fakeUpstream) Write(b []byte) (int, error) {
	select {
	case <-u.done:
		return 0, net.ErrClosed
	default:
	}
	u.mu.Lock()
	u.writes++
	u.mu.Unlock()
	if u.echo {
		select {
		case u.rx <- append([]byte(nil), b...):
		default: // full: dropped
		}
	}
	return len(b), nil
}

// LocalAddr reports the flow's distinct source address.
func (u *fakeUpstream) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(u.local) }

// Close closes the upstream once; later calls are no-ops that return nil.
func (u *fakeUpstream) Close() error {
	u.once.Do(func() { close(u.done) })
	return nil
}

// closed reports whether Close has been called.
func (u *fakeUpstream) closed() bool {
	select {
	case <-u.done:
		return true
	default:
		return false
	}
}

// wrote reports how many datagrams were written to the upstream.
func (u *fakeUpstream) wrote() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.writes
}

// fakeUDPBackend stands in for the backends behind a relay: its dial is the
// relay's dial seam, and each call opens one fakeUpstream with its own source
// address. Because the relay opens ONE connected upstream per client flow, the
// number of upstreams that carried a datagram is the number of flows the backend
// saw, which is what the "picked once per flow" assertions count.
//
// Locking discipline: ups is guarded by mu.
type fakeUDPBackend struct {
	echo bool

	mu  sync.Mutex
	ups []*fakeUpstream
}

// newFakeUDPBackend returns a backend whose upstreams echo when echo is set.
func newFakeUDPBackend(echo bool) *fakeUDPBackend {
	return &fakeUDPBackend{echo: echo}
}

// dial matches udpRelay.dial: it opens one fake upstream toward raddr, recording
// the laddr the relay asked it to bind.
func (b *fakeUDPBackend) dial(laddr, raddr *net.UDPAddr) (udpUpstream, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	u := &fakeUpstream{
		local:  netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(50000+len(b.ups))),
		remote: raddr.AddrPort(),
		laddr:  laddr,
		echo:   b.echo,
		rx:     make(chan []byte, fakeQueueDepth),
		done:   make(chan struct{}),
	}
	b.ups = append(b.ups, u)
	return u, nil
}

// dials reports how many upstreams were opened.
func (b *fakeUDPBackend) dials() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.ups)
}

// upstream returns the i-th upstream opened.
func (b *fakeUDPBackend) upstream(i int) *fakeUpstream {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ups[i]
}

// flowsSeen reports how many distinct upstreams carried at least one datagram.
func (b *fakeUDPBackend) flowsSeen() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, u := range b.ups {
		if u.wrote() > 0 {
			n++
		}
	}
	return n
}

// TestFakeUDPContract pins the fakes' own contract, so a relay test that passes
// on them is passing on the semantics a socket has: a blocked read is released by
// Close with net.ErrClosed, later calls keep returning it, and concurrent
// write/read/close is race-free.
func TestFakeUDPContract(t *testing.T) {
	t.Parallel()

	t.Run("a blocked VIP read is released by Close", func(t *testing.T) {
		c := newFakeVIPConn(netip.MustParseAddrPort("10.43.0.5:53"))
		errc := make(chan error, 1)
		go func() {
			_, _, err := c.ReadFromUDPAddrPort(make([]byte, 16))
			errc <- err
		}()
		_ = c.Close()
		select {
		case err := <-errc:
			if err != net.ErrClosed {
				t.Fatalf("blocked read returned %v, want net.ErrClosed", err)
			}
		case <-time.After(fakeHandledTimeout):
			t.Fatal("Close did not release the blocked read")
		}
		if _, _, err := c.ReadFromUDPAddrPort(make([]byte, 16)); err != net.ErrClosed {
			t.Fatalf("read after Close = %v, want net.ErrClosed", err)
		}
		if _, err := c.WriteToUDPAddrPort([]byte("x"), netip.MustParseAddrPort("10.0.0.1:1")); err != net.ErrClosed {
			t.Fatalf("write after Close = %v, want net.ErrClosed", err)
		}
		if err := c.Close(); err != nil {
			t.Fatalf("second Close = %v, want nil", err)
		}
	})

	t.Run("a blocked upstream read is released by Close", func(t *testing.T) {
		be := newFakeUDPBackend(false)
		if _, err := be.dial(nil, &net.UDPAddr{IP: net.IPv4(10, 42, 0, 1), Port: 53}); err != nil {
			t.Fatalf("fake dial: %v", err)
		}
		up := be.upstream(0)
		errc := make(chan error, 1)
		go func() {
			_, err := up.Read(make([]byte, 16))
			errc <- err
		}()
		_ = up.Close()
		select {
		case err := <-errc:
			if err != net.ErrClosed {
				t.Fatalf("blocked read returned %v, want net.ErrClosed", err)
			}
		case <-time.After(fakeHandledTimeout):
			t.Fatal("Close did not release the blocked read")
		}
		if _, err := up.Write([]byte("x")); err != net.ErrClosed {
			t.Fatalf("write after Close = %v, want net.ErrClosed", err)
		}
	})

	t.Run("deliver waits for the reader to come back", func(t *testing.T) {
		c := newFakeVIPConn(netip.MustParseAddrPort("10.43.0.5:53"))
		client := netip.MustParseAddrPort("10.0.0.1:4000")
		got := make(chan string, 2)
		go func() {
			buf := make([]byte, 16)
			for {
				n, from, err := c.ReadFromUDPAddrPort(buf)
				if err != nil {
					return
				}
				if from != client {
					got <- "wrong client " + from.String()
					continue
				}
				got <- string(buf[:n])
			}
		}()
		c.deliver(t, client, "a")
		// The barrier returned, so the reader already finished with "a".
		select {
		case s := <-got:
			if s != "a" {
				t.Fatalf("reader saw %q, want a", s)
			}
		default:
			t.Fatal("deliver returned before the reader handled the datagram")
		}
		_ = c.Close()
	})

	t.Run("concurrent write, read and close are race-free", func(t *testing.T) {
		c := newFakeVIPConn(netip.MustParseAddrPort("10.43.0.5:53"))
		be := newFakeUDPBackend(true)
		if _, err := be.dial(nil, &net.UDPAddr{IP: net.IPv4(10, 42, 0, 1), Port: 53}); err != nil {
			t.Fatalf("fake dial: %v", err)
		}
		up := be.upstream(0)
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(3)
			go func() {
				defer wg.Done()
				for j := 0; j < 200; j++ {
					_, _ = up.Write([]byte("x"))
					_, _ = c.WriteToUDPAddrPort([]byte("y"), netip.MustParseAddrPort("10.0.0.1:1"))
				}
			}()
			go func() {
				defer wg.Done()
				buf := make([]byte, 4)
				for {
					if _, err := up.Read(buf); err != nil {
						return
					}
				}
			}()
			go func() {
				defer wg.Done()
				_ = up.Close()
				_ = c.Close()
			}()
		}
		wg.Wait()
		if !up.closed() || !c.closed() {
			t.Fatal("Close did not take effect")
		}
	})
}
