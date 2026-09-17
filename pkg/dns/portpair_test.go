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

// The shared "same port on UDP and TCP" bind used by both DNS stubs in this
// package (newStubDNS in stubserver_test.go, newTemplateDNS in
// differential_integration_test.go — this file carries no build tag so it is in
// both builds).
//
// Both stubs need one port that answers on BOTH transports, because the
// resolver's TC-over-TCP refetch dials the very ip:port the UDP answer came
// from. The obvious sequence — bind UDP :0, then TCP on whatever port the
// kernel handed out — has a race that no bind ORDER removes: the UDP and TCP
// port tables are independent, so a port free for UDP can already be held for
// TCP by an unrelated process. On a host running several test binaries that
// surfaces as "bind: address already in use" and reds the whole package.
//
// The fix is to retry the PAIR: on EADDRINUSE from the TCP bind, drop the UDP
// socket and ask the kernel for a different ephemeral port. Each retry is an
// independent draw from the ephemeral range, so a handful of attempts makes the
// collision negligible while an unrelated error (permissions, address family)
// still fails immediately rather than spinning.

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// bindPairAttempts is how many independent (UDP, TCP) draws a stub makes before
// giving up.
const bindPairAttempts = 8

// bindPair binds a UDP socket and a TCP listener on the same port, retrying the
// pair when the TCP bind loses a race for that port.
//
// It is the pure core of bindSamePortPair: listenUDP and listenTCP are injected
// so the retry, the close accounting, and the error taxonomy can be exercised
// without depending on a real port collision. listenTCP is called with the port
// listenUDP obtained; on an EADDRINUSE from it the UDP socket is closed and a
// fresh pair is drawn. Any other error, or exhausting attempts, is returned and
// names the port that failed.
func bindPair(attempts int, listenUDP func() (*net.UDPConn, error), listenTCP func(port int) (net.Listener, error)) (*net.UDPConn, net.Listener, error) {
	if attempts < 1 {
		return nil, nil, fmt.Errorf("bind udp+tcp pair: attempts must be >= 1, got %d", attempts)
	}
	lastPort := 0
	var lastErr error
	for i := 0; i < attempts; i++ {
		conn, err := listenUDP()
		if err != nil {
			return nil, nil, fmt.Errorf("bind udp on 127.0.0.1:0: %w", err)
		}
		port := conn.LocalAddr().(*net.UDPAddr).Port
		ln, err := listenTCP(port)
		if err == nil {
			return conn, ln, nil
		}
		_ = conn.Close()
		if !errors.Is(err, syscall.EADDRINUSE) {
			return nil, nil, fmt.Errorf("bind tcp on port %d: %w", port, err)
		}
		lastPort, lastErr = port, err
	}
	return nil, nil, fmt.Errorf("bind udp+tcp pair: %d attempts exhausted, last port %d: %w", attempts, lastPort, lastErr)
}

// bindSamePortPair binds a loopback UDP socket and a TCP listener on the same
// ephemeral port, retrying the pair up to attempts times when the TCP bind hits
// a port another process already holds. It fails the test on any other error.
func bindSamePortPair(t *testing.T, attempts int) (*net.UDPConn, net.Listener) {
	t.Helper()
	conn, ln, err := bindPair(attempts,
		func() (*net.UDPConn, error) {
			return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		},
		func(port int) (net.Listener, error) {
			return net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		})
	if err != nil {
		t.Fatalf("stub dns bind: %v", err)
	}
	return conn, ln
}

// errAddrInUse builds the error shape the net package reports for a port another
// process already holds (*net.OpError wrapping *os.SyscallError wrapping the
// errno), so the fake listenTCP is indistinguishable from the real one as far as
// errors.Is is concerned.
func errAddrInUse() error {
	return &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
}

// fakeListener is the minimal net.Listener the injected listenTCP hands back: it
// only has to report the port it was asked for.
type fakeListener struct{ port int }

func (f *fakeListener) Accept() (net.Conn, error) { return nil, errors.New("fake listener: no accept") }
func (f *fakeListener) Close() error              { return nil }
func (f *fakeListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: f.port} }

// TestStubDNSSurvivesABusyTCPPort is the B329 gate: the stubs' bind must ride
// out a TCP port that is already taken instead of reddening the package.
func TestStubDNSSurvivesABusyTCPPort(t *testing.T) {
	// newUDP binds real loopback UDP sockets (cheap, and never the contended
	// side) while recording them, so the test can account for every bind and
	// every close. A socket that bindPair closed reports net.ErrClosed on a
	// second Close; one it left open reports nil.
	newUDP := func(conns *[]*net.UDPConn) func() (*net.UDPConn, error) {
		return func() (*net.UDPConn, error) {
			c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
			if err != nil {
				return nil, err
			}
			*conns = append(*conns, c)
			return c, nil
		}
	}
	closedCount := func(t *testing.T, conns []*net.UDPConn, keepOpen *net.UDPConn) int {
		t.Helper()
		n := 0
		for _, c := range conns {
			if c == keepOpen {
				continue
			}
			if err := c.Close(); errors.Is(err, net.ErrClosed) {
				n++
			}
		}
		return n
	}

	t.Run("retries past busy ports and returns a shared-port pair", func(t *testing.T) {
		for _, busy := range []int{0, 1, 3, bindPairAttempts - 1} {
			t.Run(fmt.Sprintf("busy=%d", busy), func(t *testing.T) {
				var conns []*net.UDPConn
				calls := 0
				var ports []int
				conn, ln, err := bindPair(bindPairAttempts, newUDP(&conns), func(port int) (net.Listener, error) {
					ports = append(ports, port)
					calls++
					if calls <= busy {
						return nil, errAddrInUse()
					}
					return &fakeListener{port: port}, nil
				})
				if err != nil {
					t.Fatalf("bindPair: unexpected error after %d busy ports: %v", busy, err)
				}
				defer func() { _ = conn.Close() }()
				defer func() { _ = ln.Close() }()

				// The pair shares one port — the TC-over-TCP refetch contract:
				// the resolver dials the TCP side at the address the UDP answer
				// came from, so addr()/port() derived from the UDP conn must be
				// the listener's port too.
				udpPort := conn.LocalAddr().(*net.UDPAddr).Port
				tcpPort := ln.Addr().(*net.TCPAddr).Port
				if udpPort != tcpPort {
					t.Errorf("pair port mismatch: udp %d, tcp %d", udpPort, tcpPort)
				}
				if got, want := len(conns), busy+1; got != want {
					t.Errorf("udp binds = %d, want %d", got, want)
				}
				if got := closedCount(t, conns, conn); got != busy {
					t.Errorf("closed udp sockets = %d, want %d", got, busy)
				}
				if got, want := len(ports), busy+1; got != want {
					t.Fatalf("tcp bind attempts = %d, want %d", got, want)
				}
				if ports[len(ports)-1] != udpPort {
					t.Errorf("last tcp bind asked for port %d, want %d", ports[len(ports)-1], udpPort)
				}
			})
		}
	})

	t.Run("exhaustion fails and names the last port", func(t *testing.T) {
		var conns []*net.UDPConn
		var lastPort int
		conn, ln, err := bindPair(3, newUDP(&conns), func(port int) (net.Listener, error) {
			lastPort = port
			return nil, errAddrInUse()
		})
		if err == nil {
			_ = conn.Close()
			_ = ln.Close()
			t.Fatal("bindPair: want an error when every attempt is busy, got nil")
		}
		if len(conns) != 3 {
			t.Errorf("udp binds = %d, want 3", len(conns))
		}
		if got := closedCount(t, conns, nil); got != 3 {
			t.Errorf("closed udp sockets = %d, want 3", got)
		}
		if !strings.Contains(err.Error(), strconv.Itoa(lastPort)) {
			t.Errorf("error %q does not name the last port %d", err, lastPort)
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Errorf("error %v does not wrap EADDRINUSE", err)
		}
	})

	t.Run("a non-EADDRINUSE error fails immediately and names the port", func(t *testing.T) {
		var conns []*net.UDPConn
		var lastPort int
		boom := errors.New("socket: permission denied")
		_, _, err := bindPair(bindPairAttempts, newUDP(&conns), func(port int) (net.Listener, error) {
			lastPort = port
			return nil, boom
		})
		if err == nil {
			t.Fatal("bindPair: want an error for a non-EADDRINUSE failure, got nil")
		}
		if !errors.Is(err, boom) {
			t.Errorf("error %v does not wrap the injected failure", err)
		}
		if len(conns) != 1 {
			t.Errorf("udp binds = %d, want 1 (no retry on a non-EADDRINUSE error)", len(conns))
		}
		if got := closedCount(t, conns, nil); got != 1 {
			t.Errorf("closed udp sockets = %d, want 1", got)
		}
		if !strings.Contains(err.Error(), strconv.Itoa(lastPort)) {
			t.Errorf("error %q does not name the port %d", err, lastPort)
		}
	})

	t.Run("a bad attempt count is an error, not a spin", func(t *testing.T) {
		if _, _, err := bindPair(0, func() (*net.UDPConn, error) {
			t.Fatal("bindPair: bound a socket with attempts=0")
			return nil, nil
		}, func(int) (net.Listener, error) { return nil, nil }); err == nil {
			t.Fatal("bindPair: want an error for attempts=0, got nil")
		}
	})

	t.Run("real OS: the helper comes up while another TCP listener is held", func(t *testing.T) {
		// This row exercises the real bind path end to end. It does NOT prove
		// the retry: the held listener's port is almost certainly not the one
		// the kernel hands the stub, so no collision is expected. It proves
		// only that the happy path still binds a shared-port pair — the retry
		// itself is proven by the injected rows above.
		held, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("hold a tcp port: %v", err)
		}
		defer func() { _ = held.Close() }()

		conn, ln := bindSamePortPair(t, bindPairAttempts)
		defer func() { _ = conn.Close() }()
		defer func() { _ = ln.Close() }()

		udpPort := conn.LocalAddr().(*net.UDPAddr).Port
		tcpPort := ln.Addr().(*net.TCPAddr).Port
		if udpPort != tcpPort {
			t.Errorf("pair port mismatch: udp %d, tcp %d", udpPort, tcpPort)
		}
		if udpPort == held.Addr().(*net.TCPAddr).Port {
			t.Errorf("stub took the held port %d", udpPort)
		}
	})
}
