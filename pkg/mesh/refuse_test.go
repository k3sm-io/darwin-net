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

package mesh

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// tcpFlag bits.
const (
	tFIN = 0x01
	tSYN = 0x02
	tRST = 0x04
	tACK = 0x10
)

// ipv4TCP builds an IPv4/TCP packet src:sport -> dst:dport with flags, seq and
// payload, with valid checksums.
func ipv4TCP(src, dst string, sport, dport uint16, flags byte, seq uint32, payload []byte) []byte {
	p := make([]byte, 40+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[6] = 0x40 // DF
	p[8] = 64
	p[9] = 6
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[20:], sport)
	binary.BigEndian.PutUint16(p[22:], dport)
	binary.BigEndian.PutUint32(p[24:], seq)
	p[32] = 5 << 4
	p[33] = flags
	binary.BigEndian.PutUint16(p[34:], 65535)
	copy(p[40:], payload)
	binary.BigEndian.PutUint16(p[10:], checksum(p[:20], 0))
	binary.BigEndian.PutUint16(p[36:], tcpChecksum(p))
	return p
}

// tcpChecksum computes the TCP checksum of an IPv4 packet with its checksum
// field read as zero.
func tcpChecksum(p []byte) uint16 {
	ihl := int(p[0]&0x0f) * 4
	seg := slices.Clone(p[ihl:])
	seg[16], seg[17] = 0, 0
	var ph [12]byte
	copy(ph[0:8], p[12:20])
	ph[9] = 6
	binary.BigEndian.PutUint16(ph[10:], uint16(len(seg)))
	return checksum(seg, sum(ph[:], 0))
}

// sum and checksum are the test's own RFC 1071 one's-complement sum.
func sum(b []byte, acc uint32) uint32 {
	for len(b) >= 2 {
		acc += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		acc += uint32(b[0]) << 8
	}
	return acc
}

func checksum(b []byte, acc uint32) uint16 {
	acc = sum(b, acc)
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return ^uint16(acc)
}

// TestRefuseSYNDecision pins when the node answers a SYN that arrived over the
// mesh with a RST: only a pure SYN to a pod address of the node's own /24 that is
// not allocated on this node. An allocated address is the kernel's to answer, an
// address outside the /24 is not this node's, the network, mesh-egress and utun
// link addresses are never pods, and an unknown allocation answers nothing.
func TestRefuseSYNDecision(t *testing.T) {
	node := netip.MustParsePrefix("100.64.1.0/24")
	allocated := func(ip netip.Addr) bool { return ip == netip.MustParseAddr("100.64.1.5") }
	const peer = "100.64.0.7"
	syn := func(dst string) []byte { return ipv4TCP(peer, dst, 40000, 8080, tSYN, 1000, nil) }
	frag := ipv4TCP(peer, "100.64.1.9", 40000, 8080, tSYN, 1000, nil)
	frag[6] |= 0x20 // more fragments
	short := syn("100.64.1.9")[:30]
	udp := syn("100.64.1.9")
	udp[9] = 17
	badLen := syn("100.64.1.9")
	binary.BigEndian.PutUint16(badLen[2:], 200)

	cases := []struct {
		name      string
		pkt       []byte
		allocated func(netip.Addr) bool
		want      bool
	}{
		{"a SYN to an unallocated pod address is refused", syn("100.64.1.9"), allocated, true},
		{"a SYN carrying data to an unallocated pod address is refused", ipv4TCP(peer, "100.64.1.9", 1, 2, tSYN, 7, []byte("hi")), allocated, true},
		{"an allocated address is the kernel's to answer", syn("100.64.1.5"), allocated, false},
		{"an address outside the node /24 is never answered", syn("100.64.2.9"), allocated, false},
		{"the mesh-egress address is never answered", syn("100.64.1.1"), allocated, false},
		{"the utun link address is never answered", syn("100.64.1.255"), allocated, false},
		{"the network address is never answered", syn("100.64.1.0"), allocated, false},
		{"a source inside the node /24 is never answered", ipv4TCP("100.64.1.20", "100.64.1.9", 1, 2, tSYN, 1, nil), allocated, false},
		{"an unknown allocation answers nothing", syn("100.64.1.9"), nil, false},
		{"a SYN-ACK is not a connection attempt", ipv4TCP(peer, "100.64.1.9", 1, 2, tSYN|tACK, 1, nil), allocated, false},
		{"a RST is never answered", ipv4TCP(peer, "100.64.1.9", 1, 2, tRST, 1, nil), allocated, false},
		{"a SYN-FIN is malformed", ipv4TCP(peer, "100.64.1.9", 1, 2, tSYN|tFIN, 1, nil), allocated, false},
		{"a bare ACK is not answered", ipv4TCP(peer, "100.64.1.9", 1, 2, tACK, 1, nil), allocated, false},
		{"a fragment is not answered", frag, allocated, false},
		{"a truncated packet is not answered", short, allocated, false},
		{"UDP is not answered", udp, allocated, false},
		{"a length beyond the buffer is not answered", badLen, allocated, false},
		{"IPv6 is not answered", append([]byte{0x60}, make([]byte, 59)...), allocated, false},
		{"an empty packet is not answered", nil, allocated, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := refuseSYN(c.pkt, node, c.allocated); got != c.want {
				t.Fatalf("refuseSYN = %v, want %v", got, c.want)
			}
		})
	}
}

// TestTCPReset pins the reset a refused SYN gets: from the SYN's destination to
// its source, ports swapped, RST|ACK acknowledging the SYN (and any data it
// carried), sequence zero, and valid IPv4 and TCP checksums. A Darwin or Linux
// client in SYN_SENT treats exactly this as ECONNREFUSED.
func TestTCPReset(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte("hello")} {
		syn := ipv4TCP("100.64.0.7", "100.64.1.9", 40000, 8080, tSYN, 0xfffffff0, payload)
		rst := tcpReset(syn)
		if len(rst) != 40 {
			t.Fatalf("reset is %d bytes, want 40", len(rst))
		}
		if rst[0] != 0x45 || rst[9] != 6 || binary.BigEndian.Uint16(rst[2:]) != 40 {
			t.Fatalf("reset IPv4 header = % x", rst[:20])
		}
		if rst[8] == 0 {
			t.Fatal("reset TTL is zero")
		}
		if got, want := netip.AddrFrom4([4]byte(rst[12:16])), netip.MustParseAddr("100.64.1.9"); got != want {
			t.Errorf("reset source = %s, want %s", got, want)
		}
		if got, want := netip.AddrFrom4([4]byte(rst[16:20])), netip.MustParseAddr("100.64.0.7"); got != want {
			t.Errorf("reset destination = %s, want %s", got, want)
		}
		if sp, dp := binary.BigEndian.Uint16(rst[20:]), binary.BigEndian.Uint16(rst[22:]); sp != 8080 || dp != 40000 {
			t.Errorf("reset ports = %d -> %d, want 8080 -> 40000", sp, dp)
		}
		if seq := binary.BigEndian.Uint32(rst[24:]); seq != 0 {
			t.Errorf("reset seq = %d, want 0", seq)
		}
		if ack, want := binary.BigEndian.Uint32(rst[28:]), uint32(0xfffffff0)+1+uint32(len(payload)); ack != want {
			t.Errorf("reset ack = %#x, want %#x (wraps)", ack, want)
		}
		if rst[32]>>4 != 5 || rst[33] != tRST|tACK {
			t.Errorf("reset data offset/flags = %#x/%#x, want 5/RST|ACK", rst[32]>>4, rst[33])
		}
		if checksum(rst[:20], 0) != 0 {
			t.Error("reset IPv4 header checksum does not verify")
		}
		if got := binary.BigEndian.Uint16(rst[36:]); got != tcpChecksum(rst) {
			t.Errorf("reset TCP checksum = %#x, want %#x", got, tcpChecksum(rst))
		}
	}
}

// fakeTUN is a tun.Device whose Read blocks until a packet is fed or a wake
// arrives (returning os.ErrDeadlineExceeded, as a past read deadline does on
// the real utun file), and whose Write records what reaches the kernel.
type fakeTUN struct {
	mu      sync.Mutex
	written [][]byte
	in      chan []byte
	woken   chan struct{}
	rearms  int
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{in: make(chan []byte, 8), woken: make(chan struct{}, 1)}
}

func (f *fakeTUN) File() *os.File           { return nil }
func (f *fakeTUN) MTU() (int, error)        { return MTU, nil }
func (f *fakeTUN) Name() (string, error)    { return "utun7", nil }
func (f *fakeTUN) Events() <-chan tun.Event { return nil }
func (f *fakeTUN) Close() error             { return nil }
func (f *fakeTUN) BatchSize() int           { return 1 }

func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case p := <-f.in:
		sizes[0] = copy(bufs[0][offset:], p)
		return 1, nil
	case <-f.woken:
		return 0, os.ErrDeadlineExceeded
	}
}

func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range bufs {
		f.written = append(f.written, slices.Clone(b[offset:]))
	}
	return len(bufs), nil
}

func (f *fakeTUN) wake() error {
	select {
	case f.woken <- struct{}{}:
	default:
	}
	return nil
}

func (f *fakeTUN) rearm() error {
	f.mu.Lock()
	f.rearms++
	f.mu.Unlock()
	return nil
}

const testOffset = 16

func batch(pkts ...[]byte) [][]byte {
	out := make([][]byte, len(pkts))
	for i, p := range pkts {
		out[i] = append(make([]byte, testOffset), p...)
	}
	return out
}

// readResult is one Read through a refuser.
type readResult struct {
	pkt []byte
	err error
}

// readAsync starts one Read through r and delivers its result.
func readAsync(r *refuser) <-chan readResult {
	ch := make(chan readResult, 1)
	go func() {
		buf := make([]byte, testOffset+MTU)
		sizes := []int{0}
		n, err := r.Read([][]byte{buf}, sizes, testOffset)
		if err == nil && n != 1 {
			err = errors.New("Read returned no packet")
		}
		if err != nil {
			ch <- readResult{nil, err}
			return
		}
		ch <- readResult{slices.Clone(buf[testOffset : testOffset+sizes[0]]), nil}
	}()
	return ch
}

// await waits a bounded time for a Read result.
func await(t *testing.T, ch <-chan readResult) []byte {
	t.Helper()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("Read: %v", r.err)
		}
		return r.pkt
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not return")
		return nil
	}
}

// TestRefuserFiltersAndInjects pins the injection seam: a refused SYN in an
// inbound batch never reaches the kernel while the rest of the batch does, and
// its reset comes back out of the device's outbound Read — waking a Read that
// was already blocked — so wireguard encrypts it to the peer. The wake's read
// deadline is cleared before the queue is drained, and never surfaces as an
// error (a Read error would close the wireguard device).
func TestRefuserFiltersAndInjects(t *testing.T) {
	node := netip.MustParsePrefix("100.64.1.0/24")
	allocated := func(ip netip.Addr) bool { return ip == netip.MustParseAddr("100.64.1.5") }
	f := newFakeTUN()
	r := newRefuser(f, func(p []byte) bool { return refuseSYN(p, node, allocated) }, f.wake, f.rearm)

	served := ipv4TCP("100.64.0.7", "100.64.1.5", 40000, 80, tSYN, 1, nil)
	refused := ipv4TCP("100.64.0.7", "100.64.1.9", 40001, 80, tSYN, 99, nil)
	data := ipv4TCP("100.64.0.7", "100.64.1.5", 40000, 80, tACK, 2, []byte("x"))

	// A Read blocked before the refusal arrives must be woken by it.
	got := readAsync(r)
	time.Sleep(20 * time.Millisecond)

	n, err := r.Write(batch(served, refused, data), testOffset)
	if err != nil || n != 3 {
		t.Fatalf("Write = %d, %v; want 3, nil (the whole batch is consumed)", n, err)
	}
	f.mu.Lock()
	written := f.written
	f.mu.Unlock()
	if len(written) != 2 || !slices.Equal(written[0], served) || !slices.Equal(written[1], data) {
		t.Fatalf("kernel received %d packets, want exactly the two not refused", len(written))
	}
	if rst := await(t, got); !slices.Equal(rst, tcpReset(refused)) {
		t.Fatalf("Read returned % x, want the refused SYN's reset", rst)
	}
	f.mu.Lock()
	rearms := f.rearms
	f.mu.Unlock()
	if rearms == 0 {
		t.Fatal("the wake's deadline was never cleared")
	}

	// Ordinary outbound traffic still flows through Read.
	out := ipv4TCP("100.64.1.5", "100.64.0.7", 80, 40000, tACK, 5, nil)
	f.in <- out
	if p := await(t, readAsync(r)); !slices.Equal(p, out) {
		t.Fatalf("outbound Read = % x, want the kernel's packet", p)
	}

	// A batch with nothing to refuse reaches the kernel unchanged.
	f.mu.Lock()
	f.written = nil
	f.mu.Unlock()
	if n, err := r.Write(batch(served, data), testOffset); err != nil || n != 2 {
		t.Fatalf("Write = %d, %v; want 2, nil", n, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.written) != 2 {
		t.Fatalf("kernel received %d packets, want 2", len(f.written))
	}
}

// TestRefuserQueueNeverBlocks pins that a flood of refused SYNs drops resets once
// the queue is full rather than stalling wireguard's receive path.
func TestRefuserQueueNeverBlocks(t *testing.T) {
	node := netip.MustParsePrefix("100.64.1.0/24")
	f := newFakeTUN()
	r := newRefuser(f, func(p []byte) bool { return refuseSYN(p, node, func(netip.Addr) bool { return false }) }, f.wake, f.rearm)
	syn := ipv4TCP("100.64.0.7", "100.64.1.9", 1, 2, tSYN, 1, nil)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 4*refuseQueue; i++ {
			_, _ = r.Write(batch(syn), testOffset)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Write blocked on a full reset queue")
	}
	if len(r.queue) != refuseQueue {
		t.Fatalf("queue holds %d resets, want it full at %d", len(r.queue), refuseQueue)
	}
}

// pipeTUN is a tun.Device over a real pollable file (an os.Pipe), so the
// production wake (utunWake's read deadline) is exercised against the Go poller
// rather than a fake.
type pipeTUN struct {
	*fakeTUN
	r *os.File
}

func (p *pipeTUN) File() *os.File { return p.r }

func (p *pipeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := p.r.Read(bufs[0][offset:])
	if n == 0 {
		return 0, err
	}
	sizes[0] = n
	return 1, err
}

// TestUTUNWakeUnblocksARealRead pins the production wake: a Read blocked on a
// pollable file is interrupted by the past deadline an injected reset sets, the
// reset is returned, and the deadline is cleared so the next Read blocks for real
// data again rather than failing.
func TestUTUNWakeUnblocksARealRead(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = pr.Close(); _ = pw.Close() })
	dev := &pipeTUN{fakeTUN: newFakeTUN(), r: pr}
	wake, rearm := utunWake(dev)
	node := netip.MustParsePrefix("100.64.1.0/24")
	r := newRefuser(dev, func(p []byte) bool { return refuseSYN(p, node, func(netip.Addr) bool { return false }) }, wake, rearm)

	got := readAsync(r)
	time.Sleep(20 * time.Millisecond)
	syn := ipv4TCP("100.64.0.7", "100.64.1.9", 40000, 80, tSYN, 1, nil)
	if _, err := r.Write(batch(syn), testOffset); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if p := await(t, got); !slices.Equal(p, tcpReset(syn)) {
		t.Fatalf("woken Read = % x, want the reset", p)
	}

	next := readAsync(r)
	time.Sleep(20 * time.Millisecond)
	if _, err := pw.Write([]byte{0x45, 1, 2, 3}); err != nil {
		t.Fatalf("pipe write: %v", err)
	}
	if p := await(t, next); !slices.Equal(p, []byte{0x45, 1, 2, 3}) {
		t.Fatalf("Read after the wake = % x, want the file's data (the deadline must be cleared)", p)
	}
}

// TestWrapTUNOnlyWithAnAllocation pins that the refusal is wired only when the
// device config carries both the node /24 and an allocation: the direct (root)
// mesh path, which passes neither, drives the utun unwrapped.
func TestWrapTUNOnlyWithAnAllocation(t *testing.T) {
	f := newFakeTUN()
	node := netip.MustParsePrefix("100.64.1.0/24")
	alloc := func(netip.Addr) bool { return true }
	for _, c := range []struct {
		name  string
		node  netip.Prefix
		alloc func(netip.Addr) bool
		want  bool
	}{
		{"no allocation", node, nil, false},
		{"no node /24", netip.Prefix{}, alloc, false},
		{"both", node, alloc, true},
	} {
		d := newWGDevice(wgLink{nodePodCIDR: c.node, allocated: c.alloc}, discardLogger())
		_, wrapped := d.wrapTUN(f, "utun7").(*refuser)
		if wrapped != c.want {
			t.Errorf("%s: wrapped = %v, want %v", c.name, wrapped, c.want)
		}
	}
}
