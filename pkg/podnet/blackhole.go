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

package podnet

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// IsPodAddress reports whether ip is a pod address of the node /24 nodeCIDR: one
// of the allocatable hosts .2 through .254. The network address, the reserved
// mesh-egress .1 (MeshEgressIP) and the .255 utun link address (MeshLinkIP) are
// not pod addresses, and nothing outside the /24 — a Service VIP, another node's
// pod — is either. An invalid or non-/24 nodeCIDR has no pod addresses.
func IsPodAddress(nodeCIDR netip.Prefix, ip netip.Addr) bool {
	if !nodeCIDR.IsValid() || !nodeCIDR.Addr().Is4() || nodeCIDR.Bits() != nodeCIDRBits {
		return false
	}
	ip = ip.Unmap()
	if !ip.Is4() || !nodeCIDR.Masked().Contains(ip) {
		return false
	}
	last := ip.As4()[3]
	return last >= 2 && last <= 254
}

// BlackholeRoutes installs and clears the lo0 blackhole host route that holds a
// pod's address while its alias is torn down. Its zero value is the production
// implementation; it writes to a PF_ROUTE routing socket and needs root to
// mutate the table.
//
// # Why
//
// Removing a pod's lo0 alias removes its /32 host route, so the address falls
// through to the cluster pod aggregate, which is routed over the mesh utun. A TCP
// connection the node still holds to that address — negotiated over lo0 with an
// lo0-sized segment — then re-routes onto the skywalk netif and overruns its GSO
// buffer, which panics the kernel. A host route `<ip> 127.0.0.1` flagged
// RTF_BLACKHOLE keeps the address on lo0, where the connection's segments are
// silently dropped until it times out.
//
// # Lifetime
//
// The route is installed right after the alias is removed and stays until the
// address is aliased again: there is no grace timer, because an established
// connection keeps retransmitting for minutes and would re-route the moment the
// route went. A pod address of this node's /24 is answered by no other node, so a
// lingering blackhole is harmless and their number is bounded by the /24. Routes
// live in the kernel and survive a daemon restart, so no state is kept here; List
// reads them back, which is how the netd daemon sweeps the blackholes of a /24 it
// no longer serves and the stale ones it finds at start.
//
// Only an address its alias manager actually aliased is blackholed: the managers
// track their aliases and skip the install for an address that was never plumbed,
// so a teardown request cannot durably blackhole an unused address.
type BlackholeRoutes struct{}

// blackholeFlags are the flags of the route BlackholeRoutes installs: a static
// host route through the loopback gateway that discards what it carries.
const blackholeFlags = unix.RTF_UP | unix.RTF_STATIC | unix.RTF_HOST | unix.RTF_GATEWAY | unix.RTF_BLACKHOLE

// routingReplyTimeout bounds the wait for the kernel's answer to an RTM_GET when
// the caller's context carries no earlier deadline.
const routingReplyTimeout = 2 * time.Second

// routeSeq numbers this process's routing requests so a reply can be matched to
// its request.
var routeSeq atomic.Int32

// Install adds the blackhole host route for ip. The alias's own host route must
// already be gone, or the kernel refuses the add as EEXIST. An existing blackhole
// for ip is success, so Install is idempotent. A cloned host route the kernel
// created for ip in the window since the alias went is a cache entry, not a
// decision: it is deleted and the add retried once. Any other route already held
// for ip is an error.
func (BlackholeRoutes) Install(ctx context.Context, ip netip.Addr) error {
	if !ip.Unmap().Is4() {
		return fmt.Errorf("install blackhole route for %s: not an IPv4 address", ip)
	}
	ip = ip.Unmap()
	for attempt := 0; ; attempt++ {
		err := writeRouteRequest(ctx, blackholeMessage(unix.RTM_ADD, ip, routeSeq.Add(1)))
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("install blackhole route for %s: %w", ip, err)
		}
		flags, found, lerr := lookupHostRoute(ctx, ip)
		if lerr != nil {
			return fmt.Errorf("install blackhole route for %s: route exists, and reading it back failed: %w", ip, lerr)
		}
		switch {
		case found && flags&unix.RTF_BLACKHOLE != 0:
			return nil
		case found && flags&unix.RTF_WASCLONED != 0 && attempt == 0:
			if err := deleteHostRoute(ctx, ip); err != nil {
				return fmt.Errorf("install blackhole route for %s: delete cloned route: %w", ip, err)
			}
		default:
			return fmt.Errorf("install blackhole route for %s: another host route is held for the address (flags %#x): %w", ip, flags, err)
		}
	}
}

// Clear removes ip's blackhole host route if there is one. It reads the host
// route back first and deletes it ONLY when it carries RTF_BLACKHOLE, so it can
// never remove a live alias's route or anything else. No host route for ip is
// success.
func (BlackholeRoutes) Clear(ctx context.Context, ip netip.Addr) error {
	if !ip.Unmap().Is4() {
		return fmt.Errorf("clear blackhole route for %s: not an IPv4 address", ip)
	}
	ip = ip.Unmap()
	flags, found, err := lookupHostRoute(ctx, ip)
	if err != nil {
		return fmt.Errorf("clear blackhole route for %s: %w", ip, err)
	}
	if !found || flags&unix.RTF_BLACKHOLE == 0 {
		return nil
	}
	if err := deleteHostRoute(ctx, ip); err != nil {
		return fmt.Errorf("clear blackhole route for %s: %w", ip, err)
	}
	return nil
}

// List returns the pod addresses of the node /24 nodeCIDR (IsPodAddress) that
// hold a blackhole host route, read from a dump of the IPv4 routing table
// (sysctl NET_RT_DUMP). Routes of any other kind, and blackholes outside the pod
// range, are not reported. Reading the table needs no privilege.
func (BlackholeRoutes) List(ctx context.Context, nodeCIDR netip.Prefix) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rib, err := xroute.FetchRIB(unix.AF_INET, xroute.RIBTypeRoute, 0)
	if err != nil {
		return nil, fmt.Errorf("list blackhole routes in %s: dump routing table: %w", nodeCIDR, err)
	}
	msgs, err := xroute.ParseRIB(xroute.RIBTypeRoute, rib)
	if err != nil {
		return nil, fmt.Errorf("list blackhole routes in %s: parse routing table: %w", nodeCIDR, err)
	}
	return blackholesIn(msgs, nodeCIDR), nil
}

// blackholesIn returns the destinations of the blackhole host routes in msgs that
// are pod addresses of nodeCIDR, in table order. It is the pure half of List.
func blackholesIn(msgs []xroute.Message, nodeCIDR netip.Prefix) []netip.Addr {
	var out []netip.Addr
	for _, msg := range msgs {
		m, ok := msg.(*xroute.RouteMessage)
		if !ok || m.Flags&unix.RTF_HOST == 0 || m.Flags&unix.RTF_BLACKHOLE == 0 || len(m.Addrs) <= unix.RTAX_DST {
			continue
		}
		dst, ok := m.Addrs[unix.RTAX_DST].(*xroute.Inet4Addr)
		if !ok {
			continue
		}
		if ip := netip.AddrFrom4(dst.IP); IsPodAddress(nodeCIDR, ip) {
			out = append(out, ip)
		}
	}
	return out
}

// deleteHostRoute writes RTM_DELETE for ip's host route; an absent route (ESRCH)
// is success.
func deleteHostRoute(ctx context.Context, ip netip.Addr) error {
	err := writeRouteRequest(ctx, blackholeMessage(unix.RTM_DELETE, ip, routeSeq.Add(1)))
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

// blackholeMessage builds the routing message for ip's blackhole host route. For
// RTM_ADD it is what route(8) builds for `add -host <ip> 127.0.0.1 -blackhole`;
// for RTM_DELETE and RTM_GET it names the host destination only. It is a pure
// function of its arguments so the encoding is tested without a socket.
func blackholeMessage(typ int, ip netip.Addr, seq int32) *xroute.RouteMessage {
	m := &xroute.RouteMessage{
		Type: typ,
		ID:   uintptr(os.Getpid()),
		Seq:  int(seq),
	}
	dst := &xroute.Inet4Addr{IP: ip.As4()}
	switch typ {
	case unix.RTM_ADD:
		m.Flags = blackholeFlags
		m.Addrs = []xroute.Addr{unix.RTAX_DST: dst, unix.RTAX_GATEWAY: &xroute.Inet4Addr{IP: [4]byte{127, 0, 0, 1}}}
	default:
		m.Flags = unix.RTF_UP | unix.RTF_HOST
		m.Addrs = []xroute.Addr{unix.RTAX_DST: dst}
	}
	return m
}

// lookupHostRoute asks the kernel (RTM_GET) for its route to ip and reports the
// route's flags when it is ip's own host route. RTM_GET answers with the
// longest-prefix match, so a reply for any other destination — the cluster
// aggregate, the default route — means ip has no host route: found is false.
func lookupHostRoute(ctx context.Context, ip netip.Addr) (flags int, found bool, err error) {
	seq := routeSeq.Add(1)
	b, err := blackholeMessage(unix.RTM_GET, ip, seq).Marshal()
	if err != nil {
		return 0, false, fmt.Errorf("marshal RTM_GET: %w", err)
	}
	reply, err := routingExchange(ctx, b, seq)
	if errors.Is(err, unix.ESRCH) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return hostRouteFlags(reply, ip)
}

// hostRouteFlags decodes an RTM_GET reply and reports its flags when it is ip's
// host route.
func hostRouteFlags(reply *xroute.RouteMessage, ip netip.Addr) (int, bool, error) {
	if reply.Err != nil {
		if errors.Is(reply.Err, unix.ESRCH) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("RTM_GET: %w", reply.Err)
	}
	if reply.Flags&unix.RTF_HOST == 0 || len(reply.Addrs) <= unix.RTAX_DST {
		return 0, false, nil
	}
	dst, ok := reply.Addrs[unix.RTAX_DST].(*xroute.Inet4Addr)
	if !ok || netip.AddrFrom4(dst.IP) != ip {
		return 0, false, nil
	}
	return reply.Flags, true, nil
}

// writeRouteRequest marshals m and writes it to a fresh routing socket; the
// write's errno is the kernel's verdict on the request.
func writeRouteRequest(ctx context.Context, m *xroute.RouteMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := m.Marshal()
	if err != nil {
		return fmt.Errorf("marshal routing message: %w", err)
	}
	fd, err := openRoutingSocket()
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return writeRouting(fd, b)
}

// routingExchange writes the RTM_GET request b and returns the kernel's reply to
// it, matched by this process's pid and seq: a routing socket also receives every
// other routing message on the host, which are skipped.
func routingExchange(ctx context.Context, b []byte, seq int32) (*xroute.RouteMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := openRoutingSocket()
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	deadline := time.Now().Add(routingReplyTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	tv := unix.NsecToTimeval(time.Until(deadline).Nanoseconds())
	if tv.Sec <= 0 && tv.Usec <= 0 {
		return nil, context.DeadlineExceeded
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, fmt.Errorf("routing socket receive timeout: %w", err)
	}
	if err := writeRouting(fd, b); err != nil {
		return nil, err
	}
	pid := uint32(os.Getpid()) // #nosec G115 -- rt_msghdr.rtm_pid is a pid_t on the wire; equality-compared only
	buf := make([]byte, 4096)
	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("routing socket: no reply to RTM_GET: %w", context.DeadlineExceeded)
		}
		n, err := unix.Read(fd, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("routing socket: no reply to RTM_GET: %w", context.DeadlineExceeded)
		}
		if err != nil {
			return nil, fmt.Errorf("routing socket read: %w", err)
		}
		if m, ok := matchReply(buf[:n], pid, seq); ok {
			return m, nil
		}
	}
}

// matchReply reports whether b is the RTM_GET reply to this process's request
// seq, and decodes it. It inspects the fixed rt_msghdr fields before parsing, so
// an unrelated message of a shape the parser rejects is skipped, not an error.
func matchReply(b []byte, pid uint32, seq int32) (*xroute.RouteMessage, bool) {
	// rt_msghdr: msglen u16, version u8, type u8, index u16, flags i32 at 8,
	// addrs i32 at 12, pid at 16, seq at 20.
	if len(b) < 24 || b[3] != unix.RTM_GET {
		return nil, false
	}
	if binary.NativeEndian.Uint32(b[16:20]) != pid || int32(binary.NativeEndian.Uint32(b[20:24])) != seq { // #nosec G115 -- rtm_seq is an int32 on the wire; equality-compared only
		return nil, false
	}
	msgs, err := xroute.ParseRIB(xroute.RIBTypeRoute, b)
	if err != nil || len(msgs) == 0 {
		return nil, false
	}
	m, ok := msgs[0].(*xroute.RouteMessage)
	return m, ok
}

// openRoutingSocket opens a PF_ROUTE socket marked close-on-exec. Darwin has no
// SOCK_CLOEXEC, so the two steps run under the runtime's ForkLock: the daemon
// forks ifconfig from other goroutines, and a child spawned in between would
// inherit a root routing-socket descriptor.
func openRoutingSocket() (int, error) {
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return -1, fmt.Errorf("open routing socket: %w", err)
	}
	return fd, nil
}

// writeRouting writes one routing message; its errno is the kernel's verdict.
func writeRouting(fd int, b []byte) error {
	for {
		n, err := unix.Write(fd, b)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n != len(b) {
			return fmt.Errorf("routing socket: short write: %d of %d bytes", n, len(b))
		}
		return nil
	}
}
