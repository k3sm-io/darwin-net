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

// This test binds real loopback UDP sockets; it needs no privilege. Run with:
//
//	CGO_ENABLED=0 go test -tags integration -run TestBindPortUDPCoexistsWithAWildcardListener ./pkg/netd/

package netd

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

// TestBindPortUDPCoexistsWithAWildcardListener reproduces the DNS VIP bind race:
// another socket holds the UDP wildcard 0.0.0.0:P with SO_REUSEADDR (as the
// Internet Sharing resolver holds *:53), and the applier's specific-address bind
// on 127.0.0.1:P must still succeed and receive the datagrams sent to it, while a
// wildcard bind is left as before (its socket carries no SO_REUSEADDR).
func TestBindPortUDPCoexistsWithAWildcardListener(t *testing.T) {
	ctx := context.Background()
	holderCfg := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) { serr = setReuseAddrForTest(int(fd)) }); err != nil {
			return err
		}
		return serr
	}}
	holder, err := holderCfg.ListenPacket(ctx, "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("hold the wildcard: %v", err)
	}
	defer func() { _ = holder.Close() }()
	port := uint16(holder.LocalAddr().(*net.UDPAddr).Port)

	a := newDarwinApplier(netip.MustParsePrefix("100.64.3.0/24"), quietLogger())

	specific := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
	f, err := a.BindPort(ctx, "udp", specific)
	if err != nil {
		t.Fatalf("BindPort(udp %s) beside a held wildcard: %v, want bound", specific, err)
	}
	pc, err := net.FilePacketConn(f)
	_ = f.Close()
	if err != nil {
		t.Fatalf("packet conn from the bound fd: %v", err)
	}
	defer func() { _ = pc.Close() }()

	sender, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(specific))
	if err != nil {
		t.Fatalf("dial %s: %v", specific, err)
	}
	defer func() { _ = sender.Close() }()
	if _, err := sender.Write([]byte("q")); err != nil {
		t.Fatalf("send to %s: %v", specific, err)
	}
	if err := pc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 16)
	n, _, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "q" {
		t.Fatalf("specific socket read = %q, %v; want the datagram sent to %s", buf[:n], err, specific)
	}

	if got := reuseAddrOf(t, pc); got == 0 {
		t.Fatalf("specific socket %s has SO_REUSEADDR off, want on", specific)
	}

	// The wildcard path is left as it was: no SO_REUSEADDR on its socket.
	wf, err := a.BindPort(ctx, "udp", netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	if err != nil {
		t.Fatalf("BindPort(udp 0.0.0.0:0): %v", err)
	}
	wpc, err := net.FilePacketConn(wf)
	_ = wf.Close()
	if err != nil {
		t.Fatalf("packet conn from the wildcard fd: %v", err)
	}
	defer func() { _ = wpc.Close() }()
	if got := reuseAddrOf(t, wpc); got != 0 {
		t.Fatalf("wildcard socket has SO_REUSEADDR %d, want off (unchanged)", got)
	}
}

// reuseAddrOf reads SO_REUSEADDR from a packet conn's socket.
func reuseAddrOf(t *testing.T, pc net.PacketConn) int {
	t.Helper()
	sc, ok := pc.(syscall.Conn)
	if !ok {
		t.Fatalf("%T is not a syscall.Conn", pc)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("raw conn: %v", err)
	}
	var v int
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		v, gerr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR)
	}); err != nil {
		t.Fatalf("control: %v", err)
	}
	if gerr != nil {
		t.Fatalf("getsockopt SO_REUSEADDR: %v", gerr)
	}
	return v
}

// setReuseAddrForTest sets SO_REUSEADDR on the holder socket without depending on
// the code under test.
func setReuseAddrForTest(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}
