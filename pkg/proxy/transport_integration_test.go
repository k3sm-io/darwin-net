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

// The transport-override dial on real loopback sockets: the TCP and UDP backends
// listen on 127.0.0.1 while the routing table publishes them at a vm /32, so
// only a dial that follows the override reaches them. The resolution itself is
// table-tested in transport_test.go. It needs no privilege; run with:
//
//	CGO_ENABLED=0 go test -tags integration -run '^TestTransportOverrideDialTarget$' ./pkg/proxy/

package proxy

import (
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// tcpBanner is a loopback TCP server standing in for a pod backend: it writes a
// one-line banner to every accepted connection and closes it, counting accepts so
// a test can assert a denied connection never reached the backend.
type tcpBanner struct {
	ln      net.Listener
	accepts atomic.Int32
	done    chan struct{}
}

// newTCPBanner listens on addr ("127.0.0.1:0" or "[::1]:0" — the two loopback
// addresses bindable on Darwin without an lo0 alias, giving tests two DISTINCT
// backend pod IPs) and serves the banner until closed.
func newTCPBanner(t *testing.T, addr string) *tcpBanner {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen banner backend %s: %v", addr, err)
	}
	b := &tcpBanner{ln: ln, done: make(chan struct{})}
	go func() {
		defer close(b.done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			b.accepts.Add(1)
			_, _ = conn.Write([]byte("ok"))
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-b.done
	})
	return b
}

// addrPort returns the backend's bound address as a netip.AddrPort.
func (b *tcpBanner) addrPort() netip.AddrPort {
	return b.ln.Addr().(*net.TCPAddr).AddrPort()
}

// endpoint returns the backend as a Ready netv1.Endpoint for the routing table.
func (b *tcpBanner) endpoint() netv1.Endpoint {
	ap := b.addrPort()
	return netv1.Endpoint{IP: ap.Addr().String(), Port: int32(ap.Port()), Ready: true}
}

// TestTransportOverrideDialTarget proves the seam at the DIAL, on both accept
// paths: with an override installed the proxy dials the live transport address
// (reaching a backend that is NOT at the published identity), and with none it is
// byte-identical to today for a host-process pod. Loopback only — no test here
// dials an off-loopback address.
func TestTransportOverrideDialTarget(t *testing.T) {
	t.Parallel()
	src := netip.MustParseAddr("10.42.0.10")

	t.Run("a: TCP — the dial follows the override to the live address", func(t *testing.T) {
		t.Parallel()
		// The backend LISTENS on loopback; the routing table PUBLISHES it at the vm
		// /32 with that same port. Only the override can bridge the two, so reaching
		// the banner is proof the dial used it.
		be := newTCPBanner(t, "127.0.0.1:0")
		port := be.addrPort().Port()

		p, table := newPolicyProxy(nil)
		table.SetTransportOverrides(map[netip.Addr]netip.Addr{vmPublished: be.addrPort().Addr()})
		key := PortKey{ClusterIP: "10.43.2.1", Port: 80, Protocol: netv1.ProtocolTCP}
		table.SetEndpoints(key, []netv1.Endpoint{{IP: vmPublished.String(), Port: int32(port), Ready: true}})

		if !handleVIP(t, p, key, src) {
			t.Fatalf("connection did not reach the backend: the dial must follow the transport override")
		}
		if got := be.accepts.Load(); got != 1 {
			t.Errorf("backend accepts = %d, want 1", got)
		}
	})

	t.Run("b: TCP — a host-process backend is unchanged, with an empty AND a populated map", func(t *testing.T) {
		t.Parallel()
		be := newTCPBanner(t, "127.0.0.1:0")
		p, table := newPolicyProxy(nil)
		key := PortKey{ClusterIP: "10.43.2.2", Port: 80, Protocol: netv1.ProtocolTCP}
		table.SetEndpoints(key, []netv1.Endpoint{be.endpoint()})

		// No override map has ever been installed: the pre-M11.3 shape exactly.
		if !handleVIP(t, p, key, src) {
			t.Errorf("host-process backend must be reached with no overrides installed")
		}
		// A populated map that does not name this backend must not disturb it.
		table.SetTransportOverrides(map[netip.Addr]netip.Addr{vmPublished: netip.MustParseAddr("192.168.64.5")})
		if !handleVIP(t, p, key, src) {
			t.Errorf("host-process backend must be reached while OTHER backends carry overrides")
		}
		// And an explicitly emptied map is the same thing again.
		table.SetTransportOverrides(nil)
		if !handleVIP(t, p, key, src) {
			t.Errorf("host-process backend must be reached after the override map is cleared")
		}
		if got := be.accepts.Load(); got != 3 {
			t.Errorf("backend accepts = %d, want 3 (every host-process dial unchanged)", got)
		}
	})

	t.Run("c: UDP — the relay's per-flow dial follows the same override", func(t *testing.T) {
		t.Parallel()
		bp, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp backend: %v", err)
		}
		defer bp.Close()
		beAP := bp.LocalAddr().(*net.UDPAddr).AddrPort()

		table := NewRoutingTable(netip.Prefix{})
		table.SetTransportOverrides(map[netip.Addr]netip.Addr{vmPublished: beAP.Addr()})
		key := PortKey{ClusterIP: "10.43.2.3", Port: 53, Protocol: netv1.ProtocolUDP}
		table.SetEndpoints(key, []netv1.Endpoint{{IP: vmPublished.String(), Port: int32(beAP.Port()), Ready: true}})

		vip, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("listen vip socket: %v", err)
		}
		r := newUDPRelay(vip, key, table, egressScope{}, time.Minute, maxUDPFlowsPerSource, nil, slog.New(slog.DiscardHandler))
		defer func() { _ = r.Close() }()

		var lastWarn time.Time
		up := r.upstreamFor(netip.AddrPortFrom(src, 5001), &lastWarn)
		if up == nil {
			t.Fatalf("flow admission failed")
		}
		if _, err := up.Write([]byte("ping")); err != nil {
			t.Fatalf("write via admitted flow: %v", err)
		}
		_ = bp.SetReadDeadline(time.Now().Add(policyTestTimeout))
		buf := make([]byte, 16)
		n, _, err := bp.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "ping" {
			t.Fatalf("backend must receive the datagram at the OVERRIDE address (read %q, err %v)", buf[:n], err)
		}
	})
}
