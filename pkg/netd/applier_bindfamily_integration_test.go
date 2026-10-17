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

// These tests bind real IPv4 sockets on 0.0.0.0 and 127.0.0.1 at ephemeral ports;
// they need no privilege. Run with:
//
//	CGO_ENABLED=0 go test -tags integration -run TestBindPortIPv4 ./pkg/netd/

package netd

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
)

// holdIPv4Wildcard binds an IPv4-only listener on 0.0.0.0 at an ephemeral port, as
// an IPv4-only process (nc, a v4 server) would, and returns its port.
func holdIPv4Wildcard(t *testing.T, network string) uint16 {
	t.Helper()
	switch network {
	case "tcp":
		ln, err := net.Listen("tcp4", "0.0.0.0:0")
		if err != nil {
			t.Skipf("no IPv4 wildcard TCP port available: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		return uint16(ln.Addr().(*net.TCPAddr).Port)
	default:
		pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
		if err != nil {
			t.Skipf("no IPv4 wildcard UDP port available: %v", err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		return uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	}
}

// TestBindPortIPv4WildcardDetectsAnIPv4Holder proves an IPv4 wildcard bind is
// IPv4-only: beside an IPv4-only process holding *:p it fails with EADDRINUSE. A
// dual-stack AF_INET6 socket on [::]:p binds beside that holder on macOS, so the
// conflict would go unseen.
func TestBindPortIPv4WildcardDetectsAnIPv4Holder(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			port := holdIPv4Wildcard(t, network)
			a := newDarwinApplier(netip.MustParsePrefix("100.64.3.0/24"), quietLogger())
			ap := netip.AddrPortFrom(netip.IPv4Unspecified(), port)
			f, err := a.BindPort(context.Background(), network, ap)
			if err == nil {
				_ = f.Close()
				t.Fatalf("BindPort(%s %s) beside an IPv4 holder succeeded, want EADDRINUSE", network, ap)
			}
			if !errors.Is(err, syscall.EADDRINUSE) {
				t.Fatalf("BindPort(%s %s) = %v, want EADDRINUSE", network, ap, err)
			}
		})
	}
}

// TestBindPortIPv4BindsAnIPv4Socket proves an IPv4 bind on a free port yields an
// IPv4 socket, not an IPv4-mapped address on an IPv6 one.
func TestBindPortIPv4BindsAnIPv4Socket(t *testing.T) {
	for _, addr := range []string{"0.0.0.0", "127.0.0.1"} {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(network+" "+addr, func(t *testing.T) {
				a := newDarwinApplier(netip.MustParsePrefix("100.64.3.0/24"), quietLogger())
				ap := netip.AddrPortFrom(netip.MustParseAddr(addr), 0)
				f, err := a.BindPort(context.Background(), network, ap)
				if err != nil {
					t.Fatalf("BindPort(%s %s): %v", network, ap, err)
				}
				defer func() { _ = f.Close() }()
				got := boundAddr(t, network, f)
				if !got.Addr().Is4() {
					t.Fatalf("BindPort(%s %s) bound %s, want an IPv4 address", network, ap, got)
				}
			})
		}
	}
}

// boundAddr reads the local address of the socket behind f.
func boundAddr(t *testing.T, network string, f *os.File) netip.AddrPort {
	t.Helper()
	var local net.Addr
	if network == "tcp" {
		ln, err := net.FileListener(f)
		if err != nil {
			t.Fatalf("file listener: %v", err)
		}
		defer func() { _ = ln.Close() }()
		local = ln.Addr()
	} else {
		pc, err := net.FilePacketConn(f)
		if err != nil {
			t.Fatalf("file packet conn: %v", err)
		}
		defer func() { _ = pc.Close() }()
		local = pc.LocalAddr()
	}
	ap, err := netip.ParseAddrPort(local.String())
	if err != nil {
		t.Fatalf("parse local addr %q: %v", local, err)
	}
	return ap
}
