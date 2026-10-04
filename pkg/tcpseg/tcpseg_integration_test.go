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

package tcpseg

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// readMaxSeg reads c's TCP_MAXSEG from the kernel.
func readMaxSeg(t *testing.T, c net.Conn) int {
	t.Helper()
	rc, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatalf("raw conn: %v", err)
	}
	var (
		v      int
		getErr error
	)
	if err := rc.Control(func(fd uintptr) {
		v, getErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG)
	}); err != nil {
		t.Fatalf("control: %v", err)
	}
	if getErr != nil {
		t.Fatalf("getsockopt TCP_MAXSEG: %v", getErr)
	}
	return v
}

// dialAndAccept connects through d to ln and returns both ends.
func dialAndAccept(t *testing.T, ln net.Listener, dial func() (net.Conn, error)) (dialed, accepted net.Conn) {
	t.Helper()
	acc := make(chan net.Conn, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		acc <- c
	}()
	dialed, err := dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = dialed.Close() })
	select {
	case accepted = <-acc:
	case err := <-errc:
		t.Fatalf("accept: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
	}
	t.Cleanup(func() { _ = accepted.Close() })
	return dialed, accepted
}

// TestDialClampsSegmentSizeAfterConnect proves the clamp on real loopback
// sockets: a connection dialed through Dialer to a listener wrapped with
// WrapListener carries MSS on both ends, while the unclamped baseline over the
// same loopback carries the lo0-sized segment (about 16332), so the clamp is
// what moved it.
func TestDialClampsSegmentSizeAfterConnect(t *testing.T) {
	t.Run("baseline: an unclamped loopback connection carries a lo0-sized segment", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		dialed, accepted := dialAndAccept(t, ln, func() (net.Conn, error) {
			return net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		})
		if got := readMaxSeg(t, dialed); got <= MSS {
			t.Fatalf("baseline dialed TCP_MAXSEG = %d, want > %d (otherwise the clamped case proves nothing)", got, MSS)
		}
		if got := readMaxSeg(t, accepted); got <= MSS {
			t.Fatalf("baseline accepted TCP_MAXSEG = %d, want > %d", got, MSS)
		}
	})

	t.Run("clamped: both ends carry MSS", func(t *testing.T) {
		raw, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		ln := WrapListener(raw)
		defer ln.Close()
		d := &Dialer{Timeout: 5 * time.Second}
		dialed, accepted := dialAndAccept(t, ln, func() (net.Conn, error) {
			return d.DialContext(context.Background(), "tcp", ln.Addr().String())
		})
		for name, c := range map[string]net.Conn{"dialed": dialed, "accepted": accepted} {
			got := readMaxSeg(t, c)
			if got > 1340 || got != MSS {
				t.Fatalf("%s TCP_MAXSEG = %d, want %d (<= 1340)", name, got, MSS)
			}
		}
	})
}
