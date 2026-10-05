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

// The per-pod relay on real loopback sockets: the "guest" listens on 127.0.0.1
// (its live lease) and the routing table publishes the pod at ::1, the second
// loopback address Darwin binds without an lo0 alias. Only the relay bridges the
// two. The in-memory twin is TestPublishedVMPodAddressRelaysToLive. It needs no
// privilege; run with:
//
//	CGO_ENABLED=0 go test -tags integration -run '^TestPublishedVMPodAddressRelaysToLiveSockets$' ./pkg/proxy/

package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// holdingGuest is a loopback TCP server standing in for a vm guest: it greets
// every connection with a banner and then holds it open until the peer closes,
// reporting each close, so a test can observe the relay tearing down an
// established connection.
type holdingGuest struct {
	ln      net.Listener
	accepts atomic.Int32
	closed  chan struct{}
	done    chan struct{}
}

func newHoldingGuest(t *testing.T, ln net.Listener) *holdingGuest {
	t.Helper()
	g := &holdingGuest{ln: ln, closed: make(chan struct{}, 16), done: make(chan struct{})}
	go func() {
		defer close(g.done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			g.accepts.Add(1)
			go func() {
				defer c.Close()
				_, _ = io.WriteString(c, "guest")
				_, _ = io.Copy(io.Discard, c)
				g.closed <- struct{}{}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-g.done
	})
	return g
}

// pairedLoopbackPort returns a listener on 127.0.0.1 whose port is also free on
// ::1, so the relay can bind the published side on the same port.
func pairedLoopbackPort(t *testing.T) (net.Listener, uint16) {
	t.Helper()
	for range 20 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen guest: %v", err)
		}
		port := uint16(ln.Addr().(*net.TCPAddr).Port)
		probe, err := net.Listen("tcp", netip.AddrPortFrom(netip.IPv6Loopback(), port).String())
		if err == nil {
			_ = probe.Close()
			return ln, port
		}
		_ = ln.Close()
	}
	t.Fatal("no port free on both 127.0.0.1 and ::1")
	return nil, 0
}

// dialWhenServed dials addr until something accepts it or the deadline passes.
func dialWhenServed(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing served %s: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// expectRefused asserts a dial to addr is refused (nothing listens there).
func expectRefused(t *testing.T, addr string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		_ = c.Close()
		t.Fatalf("dial %s succeeded; want it refused (no relay listener)", addr)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("dial %s: %v; want ECONNREFUSED", addr, err)
	}
}

// TestPublishedVMPodAddressRelaysToLiveSockets is the real-socket twin of the B440
// gate: a dial of the published address reaches the live guest, an undeclared
// port and a refused override are not served, and dropping the override closes
// the listener and the established connection before SetTransportOverrides
// returns.
func TestPublishedVMPodAddressRelaysToLiveSockets(t *testing.T) {
	published := netip.IPv6Loopback()
	live := netip.MustParseAddr("127.0.0.1")
	guestLn, port := pairedLoopbackPort(t)
	guest := newHoldingGuest(t, guestLn)
	undeclaredLn, undeclared := pairedLoopbackPort(t)
	undeclaredGuest := newHoldingGuest(t, undeclaredLn)

	tbl := NewRoutingTable(netip.Prefix{})
	p := New(tbl,
		withAliasManager(newNoopAliasManager()),
		WithVMNetPrefix(netip.MustParsePrefix("127.0.0.1/32")),
		WithLogger(slog.New(slog.DiscardHandler)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = p.Run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()

	pubAddr := netip.AddrPortFrom(published, port).String()

	t.Run("a refused override is not served", func(t *testing.T) {
		tbl.SetTransportOverrides(map[netip.Addr]VMPodTransport{published: {Live: netip.MustParseAddr("10.0.0.5"), Ports: []uint16{port}}})
		p.relays.reconcile(context.Background(), tbl.load())
		expectRefused(t, pubAddr)
	})

	tbl.SetTransportOverrides(map[netip.Addr]VMPodTransport{published: {Live: live, Ports: []uint16{port}}})
	c := dialWhenServed(t, pubAddr)
	defer c.Close()

	t.Run("the published address relays to the live guest", func(t *testing.T) {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, len("guest"))
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "guest" {
			t.Fatalf("relayed banner = %q, err %v; want %q", buf, err, "guest")
		}
		if got := guest.accepts.Load(); got != 1 {
			t.Fatalf("guest accepted %d connections, want 1", got)
		}
	})

	t.Run("an undeclared non-Service port is not relayed", func(t *testing.T) {
		expectRefused(t, netip.AddrPortFrom(published, undeclared).String())
		if got := undeclaredGuest.accepts.Load(); got != 0 {
			t.Fatalf("undeclared guest port accepted %d connections, want 0", got)
		}
	})

	t.Run("dropping the override closes the listener and the open connection", func(t *testing.T) {
		tbl.SetTransportOverrides(nil)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := c.Read(make([]byte, 1))
		if err == nil || n != 0 || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("read after drop = %d bytes, err %v; want the relay to have closed it", n, err)
		}
		select {
		case <-guest.closed:
		case <-time.After(5 * time.Second):
			t.Fatal("the live-side connection was never closed after the drop")
		}
		expectRefused(t, pubAddr)
	})
}
