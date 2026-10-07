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
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// The mesh answers, on the kernel's behalf, a TCP SYN that a peer sends over the
// tunnel to an address of this node's pod /24 that no pod holds: it drops the SYN
// before the kernel sees it and sends the peer a RST, so a dial of a deleted pod's
// address is refused at once, as it is upstream, instead of hanging for the SYN
// timeout. The kernel cannot do it: such an address has no lo0 alias (and holds a
// blackhole route, see podnet.BlackholeRoutes), IP forwarding is off, so the SYN
// is dropped silently. An ICMP host-unreachable would not do either: a client in
// SYN_SENT treats it as a soft error and keeps retrying.
//
// Every allocated address is left to the kernel, which answers it itself (a
// listener, or its own RST once the address is aliased onto the utun too).

// refuseQueue bounds the resets waiting to go out; a reset that finds it full is
// dropped (the peer's SYN is retransmitted and refused then), so a SYN flood can
// never stall wireguard's receive path.
const refuseQueue = 64

// TCP header flag bits.
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

// refuseSYN reports whether pkt, an IPv4 packet a peer sent over the mesh, is a
// connection attempt this node must refuse: an unfragmented TCP SYN (no ACK, RST
// or FIN) from outside node, the node's pod /24, to a pod address of node
// (.2–.254: never the network, the mesh-egress .1 or the utun link .255) that
// allocated says no pod holds. A nil allocated, an allocation the caller does not
// know yet, answers nothing. It is pure; anything it cannot parse is not refused.
func refuseSYN(pkt []byte, node netip.Prefix, allocated func(netip.Addr) bool) bool {
	if allocated == nil || !node.IsValid() || !node.Addr().Is4() || node.Bits() != 24 {
		return false
	}
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if ihl < 20 || total > len(pkt) || total < ihl+20 {
		return false
	}
	if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 { // MF or a fragment offset
		return false
	}
	tcp := pkt[ihl:total]
	if int(tcp[12]>>4)*4 < 20 || tcp[13]&(tcpSYN|tcpACK|tcpRST|tcpFIN) != tcpSYN {
		return false
	}
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	if node.Contains(src) || !node.Contains(dst) {
		return false
	}
	if last := dst.As4()[3]; last < 2 || last > 254 {
		return false
	}
	return !allocated(dst)
}

// tcpReset builds the RST|ACK that refuses syn, an IPv4 TCP SYN refuseSYN
// accepted: from the SYN's destination to its source, ports swapped, sequence
// zero, acknowledging the SYN and any data it carried (RFC 9293 §3.10.7.1: a
// segment to a closed port is answered <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>).
func tcpReset(syn []byte) []byte {
	ihl := int(syn[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(syn[2:4]))
	tcp := syn[ihl:total]
	segLen := uint32(total-ihl-int(tcp[12]>>4)*4) + 1 // the SYN occupies one
	r := make([]byte, 40)
	r[0] = 0x45
	binary.BigEndian.PutUint16(r[2:], 40)
	r[6] = 0x40 // DF
	r[8] = 64
	r[9] = 6
	copy(r[12:16], syn[16:20])
	copy(r[16:20], syn[12:16])
	binary.BigEndian.PutUint16(r[10:], inetChecksum(r[:20], 0))
	t := r[20:]
	copy(t[0:2], tcp[2:4])
	copy(t[2:4], tcp[0:2])
	binary.BigEndian.PutUint32(t[8:], binary.BigEndian.Uint32(tcp[4:8])+segLen)
	t[12] = 5 << 4
	t[13] = tcpRST | tcpACK
	var pseudo [12]byte
	copy(pseudo[0:8], r[12:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(t)))
	binary.BigEndian.PutUint16(t[16:], inetChecksum(t, onesSum(pseudo[:], 0)))
	return r
}

// onesSum adds b to acc as RFC 1071 16-bit words.
func onesSum(b []byte, acc uint32) uint32 {
	for len(b) >= 2 {
		acc += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		acc += uint32(b[0]) << 8
	}
	return acc
}

// inetChecksum is the RFC 1071 Internet checksum of b over the partial sum acc.
func inetChecksum(b []byte, acc uint32) uint16 {
	acc = onesSum(b, acc)
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return ^uint16(acc)
}

// refuser is the tun.Device wireguard-go drives in place of the utun: Write (the
// packets a peer sent, on their way to the kernel) drops each SYN refuse accepts
// and queues its reset; Read (the packets the kernel sends, on their way to a
// peer) returns a queued reset first, so wireguard encrypts it to the peer the
// SYN came from exactly like a kernel packet. Everything else passes through.
//
// A Read blocked on the utun does not see the queue, so a queued reset wakes it:
// wake sets a past read deadline on the utun file, the blocked Read returns
// os.ErrDeadlineExceeded, and Read clears the deadline (rearm) BEFORE it looks at
// the queue again. A wake that lands between the two is therefore either already
// seen by that look or makes the next inner Read return at once; no reset waits
// for unrelated traffic. The deadline error never leaves Read, because wireguard
// closes the device on any Read error.
type refuser struct {
	tun.Device
	refuse func(pkt []byte) bool
	queue  chan []byte
	wake   func() error
	rearm  func() error
	// wakeFailed latches a wake error so it is reported once.
	wakeFailed atomic.Bool
	onWakeErr  func(error)
}

// newRefuser wraps dev. wake and rearm set and clear the past read deadline that
// unblocks dev's Read (utunWake in production).
func newRefuser(dev tun.Device, refuse func([]byte) bool, wake, rearm func() error) *refuser {
	return &refuser{Device: dev, refuse: refuse, queue: make(chan []byte, refuseQueue), wake: wake, rearm: rearm}
}

// aLongTimeAgo is a read deadline already past; noDeadline clears one.
var (
	aLongTimeAgo = time.Unix(1, 0)
	noDeadline   time.Time
)

// utunWake returns the wake and rearm of a utun device: a past, and then no, read
// deadline on its file. The darwin utun file is non-blocking and pollable, so the
// deadline interrupts a pending Read.
func utunWake(dev tun.Device) (wake, rearm func() error) {
	f := dev.File()
	if f == nil {
		none := func() error { return errors.New("the tun device has no file to wake") }
		return none, func() error { return nil }
	}
	return func() error { return f.SetReadDeadline(aLongTimeAgo) },
		func() error { return f.SetReadDeadline(noDeadline) }
}

// Write passes the batch to the device, minus every SYN refuse accepts, whose
// resets are queued for Read. It reports the whole batch consumed.
func (r *refuser) Write(bufs [][]byte, offset int) (int, error) {
	var keep [][]byte // nil until the first refusal: the common path allocates nothing
	for i, b := range bufs {
		if !r.refuse(b[offset:]) {
			if keep != nil {
				keep = append(keep, b)
			}
			continue
		}
		if keep == nil {
			keep = append(make([][]byte, 0, len(bufs)), bufs[:i]...)
		}
		r.inject(tcpReset(b[offset:]))
	}
	if keep == nil {
		return r.Device.Write(bufs, offset)
	}
	if len(keep) > 0 {
		if _, err := r.Device.Write(keep, offset); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}

// inject queues pkt for Read, dropping it when the queue is full, and wakes a
// pending Read.
func (r *refuser) inject(pkt []byte) {
	select {
	case r.queue <- pkt:
	default:
		return
	}
	if err := r.wake(); err != nil && !r.wakeFailed.Swap(true) && r.onWakeErr != nil {
		r.onWakeErr(err)
	}
}

// Read returns a queued reset if there is one, else reads from the device; a
// wake's deadline error is absorbed and the queue looked at again.
func (r *refuser) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		select {
		case p := <-r.queue:
			sizes[0] = copy(bufs[0][offset:], p)
			return 1, nil
		default:
		}
		n, err := r.Device.Read(bufs, sizes, offset)
		if err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
			return n, err
		}
		if rerr := r.rearm(); rerr != nil {
			return n, rerr
		}
		if n > 0 {
			return n, nil
		}
	}
}
