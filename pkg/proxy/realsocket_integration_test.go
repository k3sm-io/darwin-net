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

// Real-socket helpers shared by the integration-tier proxy tests: loopback echo
// backends, a client that dials a VIP, and the free-port and listen/close waits.
// The unit tier runs the same paths on the in-memory fakes in helpers_test.go,
// nodeport_test.go, and fakeudp_test.go. These need no privilege; the tests that
// use them run with:
//
//	CGO_ENABLED=0 go test -tags integration ./pkg/proxy/

package proxy

import (
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// echoBackend is a tiny TCP server that writes a fixed id then echoes; it stands
// in for a pod backend so the proxy's data path is exercised without privilege.
type echoBackend struct {
	id string
	ln net.Listener
	ip string
	wg sync.WaitGroup
}

func newEchoBackend(t *testing.T, id, listenIP string) *echoBackend {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(listenIP, "0"))
	if err != nil {
		t.Fatalf("listen echo backend: %v", err)
	}
	b := &echoBackend{id: id, ln: ln, ip: listenIP}
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.WriteString(c, b.id)
			}(c)
		}
	}()
	return b
}

func (b *echoBackend) addrPort() (string, int32) {
	ap := b.ln.Addr().(*net.TCPAddr)
	return ap.IP.String(), int32(ap.Port)
}

func (b *echoBackend) close() {
	_ = b.ln.Close()
	b.wg.Wait()
}

// readID dials clusterIP:port and returns the backend id the proxy steered to.
func readID(t *testing.T, clusterIP string, port int32) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", hostPort(clusterIP, port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial VIP: %v", err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read from VIP: %v", err)
	}
	return string(buf)
}

// hostPort joins an IP and an int32 port for net.Dial.
func hostPort(ip string, port int32) string {
	return net.JoinHostPort(ip, strconv.Itoa(int(port)))
}

// Port windowing for freePort. Asking the kernel for :0 and immediately closing
// the listener hands out a port that ANOTHER concurrently running copy of a test
// binary can be handed too — and `go test ./...` runs one binary per package in
// parallel, several of which bind loopback ports, while the B207 stress recipe
// runs several copies of this very binary at once. A collision then surfaces as a
// listener that never comes up, or as waitClosed finding somebody else's socket on
// a port this test just released.
//
// So ports are drawn from a window derived from the process id and handed out
// monotonically within it: two concurrent processes cannot be handed the same
// port unless their pids collide modulo portWindows, and one process never reuses
// a port while an earlier test still holds it. Each candidate is still verified
// free by binding it, so an unrelated process squatting the window is skipped
// rather than fatal.
const (
	portWindowBase = 20000
	portWindowSize = 128
	portWindows    = 300
)

// portCursor walks this process's window; it is never reset, so a port is not
// handed out twice even across sequential tests in one binary.
var portCursor atomic.Int32

// freePort returns a TCP port currently free on ip, drawn from this process's
// port window (see above). The bind-and-release TOCTOU against an unrelated
// process on the box remains — it cannot be closed without holding the socket the
// caller is about to bind — but the collision this package can actually cause,
// between its own concurrent test binaries, is gone.
func freePort(t *testing.T, ip string) int32 {
	t.Helper()
	base := int32(portWindowBase + (os.Getpid()%portWindows)*portWindowSize)
	for i := 0; i < portWindowSize; i++ {
		port := base + portCursor.Add(1)%portWindowSize
		ln, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(int(port))))
		if err != nil {
			continue // squatted by another process; try the next slot
		}
		_ = ln.Close()
		return port
	}
	t.Fatalf("no free port in this process's window [%d,%d)", base, base+portWindowSize)
	return 0
}

func waitListen(t *testing.T, ip string, port int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", hostPort(ip, port), 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener on %s:%d never came up", ip, port)
}

func waitClosed(t *testing.T, ip string, port int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", hostPort(ip, port), 200*time.Millisecond)
		if err != nil {
			return
		}
		_ = c.Close()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener on %s:%d never closed", ip, port)
}
