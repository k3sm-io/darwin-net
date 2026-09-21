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
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"syscall"

	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// ErrRouteNotInstalled is returned when a peer route the mesh programmed is absent
// from the kernel routing table — or present but bound to another interface — when
// the applier reads the table back. It is a hard failure, never a warning: an
// uninstalled peer route sends every packet for that peer's pods to the host's
// default gateway, which is a silent cross-node blackhole.
var ErrRouteNotInstalled = errors.New("mesh: kernel route not installed")

// Route is one IPv4 route as the KERNEL reports it: the destination prefix and the
// interface it is bound to. It is what the applier verifies against, so it carries
// what the kernel actually holds — never what a command claimed to have done.
type Route struct {
	// Prefix is the masked destination prefix (a host route is a /32).
	Prefix netip.Prefix
	// Interface is the name of the interface the route is bound to ("utun6").
	Interface string
}

// routeTable is the kernel routing-table seam the mesh applier drives. It is
// defined here, at the consumer, per the standards: the production implementation
// mutates by writing RTM_ADD / RTM_DELETE messages to a PF_ROUTE socket and reads
// back through the kernel's own PF_ROUTE table dump, while unit tests substitute a
// fake so the apply/verify/fail-loudly cycle is exercised without privilege.
//
// The seam is (mutate, read-back) rather than (mutate) alone because a mutation's
// verdict is not the same claim as the table's state. The routing-socket write
// returns the kernel's errno for the REQUEST (EEXIST, ESRCH, ENETUNREACH on an
// addressless utun), which is cheap and immediate; it does not prove what the
// table holds afterwards, and the applier once shipped believing a mutation's
// success report (route(8)'s exit status, which was 0 on a rejected write) while
// the table held nothing. Only List is authoritative.
type routeTable interface {
	// Add installs a route for prefix bound to iface. It returns a report of the
	// request and its verdict, which is DIAGNOSTIC ONLY (it is quoted back in the
	// divergence error, never parsed for a verdict), plus an error if the kernel
	// refused the request or the request could not be made.
	Add(ctx context.Context, prefix netip.Prefix, iface string) (string, error)
	// Delete removes the route for prefix bound to iface, with the same diagnostic
	// report contract as Add. Deleting an absent route is not an error.
	Delete(ctx context.Context, prefix netip.Prefix, iface string) (string, error)
	// List returns the IPv4 routes the kernel currently holds. It is the only
	// authoritative answer to "did the route land".
	List(ctx context.Context) ([]Route, error)
}

// kernelRouteTable is the production routeTable on darwin: RTM_ADD / RTM_DELETE
// written to a PF_ROUTE socket for the mutation (the message route(8) would build
// for `-net <prefix> -interface <iface>`, with the write's errno as the kernel's
// verdict), the kernel's PF_ROUTE table dump (sysctl NET_RT_DUMP, decoded by
// golang.org/x/net/route) for the read-back. It performs no work at construction
// and holds no state; the routing table itself is the state.
type kernelRouteTable struct {
	// write delivers one marshalled routing message to the kernel and returns the
	// write's error. nil means a fresh PF_ROUTE socket per message (production);
	// tests substitute a recorder so the request and the errno mapping are pinned
	// without privilege.
	write func([]byte) error
}

// Add writes RTM_ADD for prefix bound to iface. EEXIST is returned as an error
// like any other refusal: the route may be bound to another interface, and the
// caller's read-back is what decides whether the one in the table is ours.
func (t kernelRouteTable) Add(ctx context.Context, prefix netip.Prefix, iface string) (string, error) {
	return t.request(ctx, unix.RTM_ADD, prefix, iface)
}

// Delete writes RTM_DELETE for prefix bound to iface. A route that is already
// gone answers ESRCH and is not an error — teardown is idempotent and the caller
// verifies absence by reading the table back.
func (t kernelRouteTable) Delete(ctx context.Context, prefix netip.Prefix, iface string) (string, error) {
	report, err := t.request(ctx, unix.RTM_DELETE, prefix, iface)
	if errors.Is(err, unix.ESRCH) {
		return report, nil
	}
	return report, err
}

// List decodes the kernel's IPv4 routing table into Route values. Messages the
// mesh cannot express (a non-IPv4 destination, a route with no destination) are
// skipped rather than failing the read-back: the applier asks only whether ITS
// prefixes are present, and an unrelated exotic entry must not wedge the mesh.
func (kernelRouteTable) List(_ context.Context) ([]Route, error) {
	rib, err := xroute.FetchRIB(unix.AF_INET, xroute.RIBTypeRoute, 0)
	if err != nil {
		return nil, fmt.Errorf("fetch kernel routing table: %w", err)
	}
	msgs, err := xroute.ParseRIB(xroute.RIBTypeRoute, rib)
	if err != nil {
		return nil, fmt.Errorf("parse kernel routing table: %w", err)
	}
	names, err := interfaceNames()
	if err != nil {
		return nil, err
	}
	out := make([]Route, 0, len(msgs))
	for _, m := range msgs {
		rm, ok := m.(*xroute.RouteMessage)
		if !ok {
			continue
		}
		if rm.Flags&unix.RTF_UP == 0 {
			continue
		}
		p, ok := routeMessagePrefix(rm)
		if !ok {
			continue
		}
		out = append(out, Route{Prefix: p, Interface: names[rm.Index]})
	}
	return out, nil
}

// routeMessagePrefix extracts the masked destination prefix from a routing
// message. A message with no netmask (or one flagged RTF_HOST) is a host route, so
// it decodes as a /32.
func routeMessagePrefix(rm *xroute.RouteMessage) (netip.Prefix, bool) {
	if len(rm.Addrs) <= unix.RTAX_DST {
		return netip.Prefix{}, false
	}
	dst, ok := rm.Addrs[unix.RTAX_DST].(*xroute.Inet4Addr)
	if !ok {
		return netip.Prefix{}, false
	}
	bits := 32
	if rm.Flags&unix.RTF_HOST == 0 && len(rm.Addrs) > unix.RTAX_NETMASK {
		if mask, ok := rm.Addrs[unix.RTAX_NETMASK].(*xroute.Inet4Addr); ok {
			ones, size := net.IPMask(mask.IP[:]).Size()
			if size != 32 {
				// A non-contiguous mask has no prefix length; the mesh only ever
				// installs contiguous /24s, so such an entry is simply not ours.
				return netip.Prefix{}, false
			}
			bits = ones
		}
	}
	return netip.PrefixFrom(netip.AddrFrom4(dst.IP), bits).Masked(), true
}

// interfaceNames maps interface index to name for decoding routing messages.
func interfaceNames() (map[int]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	names := make(map[int]string, len(ifaces))
	for _, i := range ifaces {
		names[i.Index] = i.Name
	}
	return names, nil
}

// request builds the routing message for one prefix, writes it to the kernel, and
// returns a report of the request. The errno from the write IS the verdict on the
// request (see routeTable); it is returned wrapped so callers can match it with
// errors.Is, and the report names the request it answers.
func (t kernelRouteTable) request(ctx context.Context, typ int, prefix netip.Prefix, iface string) (string, error) {
	report := fmt.Sprintf("%s %s -interface %s", routeTypeName(typ), prefix, iface)
	if err := ctx.Err(); err != nil {
		return report, err
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return report, fmt.Errorf("resolve interface: %w", err)
	}
	b, err := routeMessage(typ, prefix, iface, ifi.Index).Marshal()
	if err != nil {
		return report, fmt.Errorf("marshal: %w", err)
	}
	write := t.write
	if write == nil {
		write = writeRoutingSocket
	}
	if err := write(b); err != nil {
		return report, fmt.Errorf("routing socket write: %w", err)
	}
	return report + ": accepted", nil
}

// routeMessage is the RTM_ADD or RTM_DELETE request for prefix bound to iface —
// the message route(8) builds for `-net <prefix> -interface <iface>`: RTF_UP and
// RTF_STATIC, no RTF_GATEWAY (the next hop is the link itself, so the gateway is
// the interface's own AF_LINK address, carrying its index), no RTF_HOST (the
// netmask says how wide the route is). It is a pure function of its arguments so
// the encoding is table-tested without a socket.
func routeMessage(typ int, prefix netip.Prefix, iface string, ifindex int) *xroute.RouteMessage {
	prefix = prefix.Masked()
	addrs := make([]xroute.Addr, unix.RTAX_NETMASK+1)
	addrs[unix.RTAX_DST] = &xroute.Inet4Addr{IP: prefix.Addr().As4()}
	addrs[unix.RTAX_GATEWAY] = &xroute.LinkAddr{Index: ifindex, Name: iface}
	var mask [4]byte
	copy(mask[:], net.CIDRMask(prefix.Bits(), 32))
	addrs[unix.RTAX_NETMASK] = &xroute.Inet4Addr{IP: mask}
	return &xroute.RouteMessage{
		Type:  typ,
		Flags: unix.RTF_UP | unix.RTF_STATIC,
		ID:    uintptr(os.Getpid()),
		Addrs: addrs,
	}
}

// writeRoutingSocket delivers one routing message to the kernel over a fresh
// PF_ROUTE socket. The write is synchronous: its error is the kernel's verdict on
// the request, so nothing is read back from the socket.
func writeRoutingSocket(b []byte) error {
	// Darwin has no SOCK_CLOEXEC, so the socket is created and marked
	// close-on-exec in two syscalls. The daemon forks (ifconfig, pfctl) from
	// other goroutines, and a child spawned in that window would inherit a root
	// routing-socket fd; the runtime's ForkLock is what closes the window, as it
	// does for every fd os and net create.
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer unix.Close(fd)
	for {
		n, err := unix.Write(fd, b)
		if errors.Is(err, unix.EINTR) {
			continue // a signal, not a verdict on the request
		}
		if err != nil {
			return err
		}
		if n != len(b) {
			return fmt.Errorf("short write: %d of %d bytes", n, len(b))
		}
		return nil
	}
}

// routeTypeName renders a routing message type for reports.
func routeTypeName(typ int) string {
	switch typ {
	case unix.RTM_ADD:
		return "RTM_ADD"
	case unix.RTM_DELETE:
		return "RTM_DELETE"
	default:
		return fmt.Sprintf("RTM_%d", typ)
	}
}

// prefixesOn returns the set of prefixes in have that are bound to iface.
func prefixesOn(have []Route, iface string) map[netip.Prefix]struct{} {
	on := make(map[netip.Prefix]struct{}, len(have))
	for _, r := range have {
		if r.Interface == iface {
			on[r.Prefix] = struct{}{}
		}
	}
	return on
}

// sortedPrefixes returns the keys of a prefix set in ascending address order, so
// every apply issues its route commands and reports its divergences in a stable
// order.
func sortedPrefixes(set map[netip.Prefix]struct{}) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Addr().Compare(out[j].Addr()); c != 0 {
			return c < 0
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out
}

// routeReport renders the routing socket's account of an add for the divergence
// error. The empty report is its own diagnosis: nothing was added this time round,
// so the route was verified by an earlier apply and has since left the table (the
// utun went away, or something outside the mesh removed it).
func routeReport(report string) string {
	if report == "" {
		return " (no add was issued: the route was verified by an earlier apply and has since disappeared)"
	}
	return fmt.Sprintf(" (the routing socket reported %q)", report)
}

// formatPrefixes renders a prefix list for an error message.
func formatPrefixes(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}
