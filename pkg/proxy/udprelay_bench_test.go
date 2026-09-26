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
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// The UDP relay has ONE dispatcher goroutine (the VIP socket reader) and one
// reader goroutine per flow. Every datagram in either direction stamps the flow's
// lastActivity, so the cost of that stamp — and what it contends with — bounds the
// relay's throughput. These benchmarks measure it three ways:
//
//   - BenchmarkUDPRelayDatagram: the full loopback round trip through a live relay
//     with many concurrent client flows (syscall-dominated; the honest end-to-end).
//   - BenchmarkUDPFlowTouch: the stamp itself under N concurrent readers.
//   - BenchmarkUDPRelayDispatchUnderReaders: the dispatcher's existing-flow fast
//     path while N readers stamp concurrently — the stall that gates every VIP.

// quietLogger discards relay logs so logging cost is not what gets measured.
func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// benchEcho is a multi-reader loopback UDP echo backend: several goroutines read
// one socket so the backend is never the serialization point under test.
func benchEcho(b *testing.B, readers int) (net.PacketConn, func()) {
	b.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen echo backend: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 2048)
			for {
				n, addr, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				_, _ = pc.WriteTo(buf[:n], addr)
			}
		}()
	}
	return pc, func() { _ = pc.Close(); wg.Wait() }
}

// benchRelay stands up a live relay on a loopback VIP fronting backend, with a
// long idle timeout so the sweeper never reaps a benchmark flow mid-run.
func benchRelay(b *testing.B, backend net.Addr) (*udpRelay, *net.UDPAddr) {
	b.Helper()
	vip, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatalf("listen vip: %v", err)
	}
	vipAddr := vip.LocalAddr().(*net.UDPAddr)
	be := backend.(*net.UDPAddr)
	key := PortKey{ClusterIP: vipAddr.IP.String(), Port: int32(vipAddr.Port), Protocol: netv1.ProtocolUDP}
	tbl := NewRoutingTable(netip.Prefix{})
	tbl.SetEndpoints(key, []netv1.Endpoint{{IP: be.IP.String(), Port: int32(be.Port), Ready: true}})
	r := newUDPRelay(vip, key, tbl, egressScope{}, time.Hour, maxUDPFlowsPerSource, newUDPBudget(MaxUDPFlows, MaxUDPFlows), quietLogger())
	r.start()
	return r, vipAddr
}

// BenchmarkUDPRelayDatagram round-trips one datagram per op through a live relay.
// Each parallel goroutine is its own client socket, hence its own flow and its own
// relay reader goroutine. drops counts round trips that timed out (UDP is lossy;
// a non-zero drop count inflates ns/op by the deadline and must be reported).
func BenchmarkUDPRelayDatagram(b *testing.B) {
	be, stopEcho := benchEcho(b, 4)
	defer stopEcho()
	r, vipAddr := benchRelay(b, be.LocalAddr())
	defer func() { _ = r.Close() }()

	payload := make([]byte, 64)
	var drops atomic.Int64
	b.ReportAllocs()
	b.SetParallelism(4) // 4 × GOMAXPROCS concurrent flows
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		c, err := net.DialUDP("udp", nil, vipAddr)
		if err != nil {
			b.Errorf("dial vip: %v", err)
			return
		}
		defer c.Close()
		buf := make([]byte, 2048)
		for pb.Next() {
			if _, err := c.Write(payload); err != nil {
				b.Errorf("write: %v", err)
				return
			}
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := c.Read(buf); err != nil {
				drops.Add(1)
			}
		}
	})
	b.StopTimer()
	b.ReportMetric(float64(drops.Load()), "drops")
}

// benchFlows returns a relay (never started: no sockets) pre-populated with n
// flows keyed the way the dispatcher keys them, plus the client addresses that
// hit those keys. The flows' upstream is nil: the fast path returns it without
// dereferencing, and nothing here forwards a datagram.
func benchFlows(n int) (*udpRelay, []netip.AddrPort, []*udpFlow) {
	r := newUDPRelay(nil, PortKey{}, nil, egressScope{}, time.Hour, n, nil, quietLogger())
	addrs := make([]netip.AddrPort, n)
	flows := make([]*udpFlow, n)
	for i := range addrs {
		a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), uint16(40000+i))
		fl := &udpFlow{client: a, srcIP: a.Addr()}
		r.flows[a] = fl
		addrs[i], flows[i] = a, fl
	}
	return r, addrs, flows
}

// BenchmarkUDPFlowTouch measures the per-datagram activity stamp under concurrent
// readers, each goroutine stamping its own flow — the reader side of the relay
// with the socket cost removed.
func BenchmarkUDPFlowTouch(b *testing.B) {
	const flows = 64
	r, _, fls := benchFlows(flows)
	var next atomic.Int64
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		fl := fls[int(next.Add(1)-1)%flows]
		for pb.Next() {
			r.touch(fl)
		}
	})
}

// BenchmarkUDPRelayDispatchUnderReaders measures the dispatcher's existing-flow
// fast path (upstreamFor on a known client) while readers stamp their flows as fast
// as they can. The dispatcher is a single goroutine, so every stall it takes here is
// a stall for every flow on the VIP.
//
// SYNTHETIC: this isolates the contention mechanism, it is not a traffic shape.
// Real readers stamp once per upstream datagram, between two syscalls; here eight
// goroutines stamp back-to-back with no I/O, which is the worst case the dispatcher
// can meet, not a typical one. Read it as "how much does one dispatcher lookup pay
// when readers are as hostile as they can be", and read BenchmarkUDPRelayDatagram
// for what a loopback round trip actually costs.
func BenchmarkUDPRelayDispatchUnderReaders(b *testing.B) {
	const flows = 64
	const readers = 8
	r, addrs, fls := benchFlows(flows)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func(fl *udpFlow) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					r.touch(fl)
				}
			}
		}(fls[i])
	}

	var lastWarn time.Time
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.upstreamFor(addrs[i%flows], &lastWarn)
	}
	b.StopTimer()
	close(stop)
	wg.Wait()
}
