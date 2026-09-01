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
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strings"

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
// mutates through route(8) and reads back through the kernel's own PF_ROUTE table
// dump, while unit tests substitute a fake so the apply/verify/fail-loudly cycle is
// exercised without privilege.
//
// The seam is (mutate, read-back) rather than (mutate) alone because the mutation
// cannot be trusted on macOS: route(8) exits 0 even when its routing-socket write
// was rejected by the kernel — an addressless utun makes every RTM_ADD fail with
// ENETUNREACH, route(8) prints "writing to routing socket: Network is unreachable"
// and still exits 0. An applier that believed the exit status reported peer routes
// that were never in the table. Only List is authoritative.
type routeTable interface {
	// Add installs a route for prefix bound to iface. It returns the tool's own
	// report of what it did, which is DIAGNOSTIC ONLY (it is quoted back in the
	// divergence error, never parsed for a verdict), plus an error if the tool
	// itself failed.
	Add(ctx context.Context, prefix netip.Prefix, iface string) (string, error)
	// Delete removes the route for prefix bound to iface, with the same diagnostic
	// report contract as Add. Deleting an absent route is not an error.
	Delete(ctx context.Context, prefix netip.Prefix, iface string) (string, error)
	// List returns the IPv4 routes the kernel currently holds. It is the only
	// authoritative answer to "did the route land".
	List(ctx context.Context) ([]Route, error)
}

// kernelRouteTable is the production routeTable on darwin: route(8) for the
// mutation, the kernel's PF_ROUTE table dump (sysctl NET_RT_DUMP, decoded by
// golang.org/x/net/route) for the read-back. It performs no work at construction
// and holds no state; the routing table itself is the state.
type kernelRouteTable struct{}

// Add runs `route -n add -net <prefix> -interface <iface>`.
func (kernelRouteTable) Add(ctx context.Context, prefix netip.Prefix, iface string) (string, error) {
	return runRoute(ctx, "add", prefix, iface)
}

// Delete runs `route -n delete -net <prefix> -interface <iface>`. A route that is
// already gone reports "not in table" and is not an error — teardown is idempotent
// and the caller verifies absence by reading the table back.
func (kernelRouteTable) Delete(ctx context.Context, prefix netip.Prefix, iface string) (string, error) {
	out, err := runRoute(ctx, "delete", prefix, iface)
	if err != nil && strings.Contains(out, "not in table") {
		return out, nil
	}
	return out, err
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

// runRoute invokes route(8) for one prefix. Its exit status is reported but is NOT
// authoritative (see routeTable); the combined output is returned for diagnostics.
func runRoute(ctx context.Context, verb string, prefix netip.Prefix, iface string) (string, error) {
	args := []string{"-n", verb, "-net", prefix.String(), "-interface", iface}
	out, err := exec.CommandContext(ctx, "route", args...).CombinedOutput()
	report := string(bytes.TrimSpace(out))
	if err != nil {
		return report, fmt.Errorf("route %v: %w: %s", args, err, report)
	}
	return report, nil
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

// routeReport renders route(8)'s own account of an add for the divergence error.
// The empty report is its own diagnosis: nothing was added this time round, so the
// route was verified by an earlier apply and has since left the table (the utun
// went away, or something outside the mesh removed it).
func routeReport(report string) string {
	if report == "" {
		return " (no add was issued: the route was verified by an earlier apply and has since disappeared)"
	}
	return fmt.Sprintf(" (route(8) reported %q — it exits 0 even when the kernel rejects the write)", report)
}

// formatPrefixes renders a prefix list for an error message.
func formatPrefixes(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}
