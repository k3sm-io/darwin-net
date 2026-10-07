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
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	netv1 "k3sm.io/apis/net/v1"
)

// MSS is the TCP segment size every clamped connection is lowered to: the mesh
// utun MTU minus the IPv4 and TCP headers (40 bytes) minus the TCP timestamp
// option (12 bytes) — exactly what XNU derives for a connection routed over the
// utun, and what getsockopt(TCP_MAXSEG) reports for one. A connection negotiated
// over lo0 carries about 16332 instead, which is too large for a skywalk netif's
// GSO packet-pool buffer if the connection re-routes onto the utun. TCP_MAXSEG
// is settable on macOS only after connect, and only downward, so the clamp is
// applied to the established connection.
const MSS = int(netv1.DefaultMeshMTU) - 40 - 12

// Dialer dials connections and clamps the segment size of every TCP connection
// to MSS before returning it. Its zero value is usable and behaves like a zero
// net.Dialer plus the clamp.
//
// It deliberately does not embed net.Dialer: a promoted Dial or DialContext
// would return an unclamped connection.
type Dialer struct {
	// Timeout bounds the connect, as net.Dialer.Timeout does. Zero means no
	// timeout beyond the context's.
	Timeout time.Duration
	// KeepAlive is the TCP keep-alive period, as net.Dialer.KeepAlive: zero
	// selects the net package default, a negative value disables keep-alives.
	KeepAlive time.Duration
	// LocalAddr is the local address to dial from, as net.Dialer.LocalAddr. Nil
	// lets the kernel choose the source.
	LocalAddr net.Addr
}

// DialContext dials address on network as net.Dialer.DialContext does, then
// clamps the connection's TCP segment size to MSS. A connection that is not TCP
// is returned untouched. If the clamp fails the connection is closed and the
// error returned: a connection whose segment size could not be lowered is never
// handed to the caller.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	nd := net.Dialer{Timeout: d.Timeout, KeepAlive: d.KeepAlive, LocalAddr: d.LocalAddr}
	c, err := nd.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return clampDialed(c, network, address)
}

// clampDialed clamps a freshly dialed connection, closing it and returning the
// error when the clamp fails.
func clampDialed(c net.Conn, network, address string) (net.Conn, error) {
	if err := clamp(c); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("dial %s %s: %w", network, address, err)
	}
	return c, nil
}

// Listener wraps a net.Listener so every accepted TCP connection has its segment
// size clamped to MSS. Build one with WrapListener.
type Listener struct {
	inner net.Listener
}

// WrapListener returns l with the segment clamp applied to every connection it
// accepts. Wrap the raw TCP listener, not a TLS listener built over it: a
// tls.Conn exposes no socket, so its segment size cannot be reached.
func WrapListener(l net.Listener) *Listener {
	return &Listener{inner: l}
}

// Accept waits for the next connection and clamps its TCP segment size to MSS.
// A connection whose clamp fails is closed and skipped, and Accept waits for the
// next one; only an error from the wrapped listener is returned.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		c, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}
		if err := clamp(c); err != nil {
			slog.Debug("closing accepted connection whose TCP segment size could not be clamped",
				"remote", c.RemoteAddr().String(), "err", err)
			_ = c.Close()
			continue
		}
		return c, nil
	}
}

// Close closes the wrapped listener.
func (l *Listener) Close() error { return l.inner.Close() }

// Addr returns the wrapped listener's address.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// getMaxSeg and setMaxSeg are the socket-option calls the clamp makes. They are
// package-level so a unit test can record them without a real socket; nothing
// else assigns them.
var (
	getMaxSeg = func(fd int) (int, error) {
		return unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_MAXSEG)
	}
	setMaxSeg = func(fd, mss int) error {
		return unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_MAXSEG, mss)
	}
)

// clamp lowers c's TCP segment size to MSS. A connection is treated as TCP when
// its local address is a *net.TCPAddr and it exposes its socket (as *net.TCPConn
// does); anything else — a unix socket, a wrapped connection — passes through
// untouched.
func clamp(c net.Conn) error {
	if _, ok := c.LocalAddr().(*net.TCPAddr); !ok {
		return nil
	}
	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return fmt.Errorf("clamp tcp segment size: raw conn: %w", err)
	}
	var clampErr error
	if err := rc.Control(func(fd uintptr) { clampErr = clampFD(int(fd)) }); err != nil {
		return fmt.Errorf("clamp tcp segment size: %w", err)
	}
	return clampErr
}

// clampFD reads fd's TCP_MAXSEG and lowers it to MSS when it is larger. A socket
// already at or below MSS is left alone: XNU refuses to raise TCP_MAXSEG, and a
// path that negotiated a smaller segment must not fail.
func clampFD(fd int) error {
	cur, err := getMaxSeg(fd)
	if err != nil {
		return fmt.Errorf("clamp tcp segment size: get TCP_MAXSEG: %w", err)
	}
	if cur <= MSS {
		return nil
	}
	if err := setMaxSeg(fd, MSS); err != nil {
		return fmt.Errorf("clamp tcp segment size: set TCP_MAXSEG %d (was %d): %w", MSS, cur, err)
	}
	return nil
}
