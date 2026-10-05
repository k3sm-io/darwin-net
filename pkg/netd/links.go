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

package netd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/mesh"
)

// bridgeIface is the Thunderbolt Bridge interface macOS puts every Thunderbolt
// port into. The daemon only ever removes and restores Thunderbolt MEMBERS; it
// never downs the bridge or touches another member.
const bridgeIface = "bridge0"

// offloadFlags are the interface options that must be off on a direct-link port:
// a socket that moves between a TSO interface and the tunnel is the kernel-fault
// class the mesh keeps out by holding one MSS for every path.
var offloadFlags = []string{"TSO4", "TSO6", "LRO"}

// errNoSuchInterface reports an ifconfig read of an interface that is gone.
var errNoSuchInterface = errors.New("netd: interface does not exist")

// ConfigureLink configures a direct-link port the server validated. The order is
// the safety argument:
//
//  1. bridge0 member removal, read back from `ifconfig bridge0`. An absent member
//     (or no bridge at all) is success. A removal that does not take returns an
//     error BEFORE anything else is touched, so a failure here leaves no alias.
//  2. When the cable now leads to a different peer, the direct routes through the
//     old peer are withdrawn from the mesh and only then is its host route
//     removed.
//  3. The port's /32 alias (`ifconfig enX inet A A netmask 255.255.255.255
//     alias`, the form the utun address uses).
//  4. Offload off: `ifconfig enX -tso` and `-lro` (macOS's ifconfig spells the
//     TSO switch -tso, covering IPv4 and IPv6, and refuses -tso4/-tso6). A driver
//     that lacks a switch refuses it, so the commands' verdicts are not trusted:
//     the read-back below requires TSO4, TSO6 and LRO all absent.
//  5. The on-link host route to the peer, when one is given, verified in the
//     kernel table.
//  6. Kernel read-back of the alias and the offload state.
//
// A fresh link that fails at 3–6 has its alias and host route removed again:
// never half-configured. Every change is an Info line under the daemon's logger.
func (a *darwinApplier) ConfigureLink(ctx context.Context, spec LinkSpec) error {
	a.linkMu.Lock()
	defer a.linkMu.Unlock()
	prev, had := a.links[spec.Iface]

	if err := a.removeBridgeMember(ctx, spec.Iface); err != nil {
		return err
	}
	if had && prev.PeerLinkIP.IsValid() && prev.PeerLinkIP != spec.PeerLinkIP {
		if err := a.withdraw(ctx, spec.Iface); err != nil {
			return fmt.Errorf("withdraw the direct routes through %s on %s: %w", prev.PeerLinkIP, spec.Iface, err)
		}
		if err := a.hostRoutes.Remove(ctx, prev.PeerLinkIP, spec.Iface); err != nil {
			return fmt.Errorf("remove the host route to the previous peer %s on %s: %w", prev.PeerLinkIP, spec.Iface, err)
		}
		a.log.Info("netd: direct link re-pointed", "iface", spec.Iface, "from", prev.PeerLinkIP.String(), "to", spec.PeerLinkIP.String())
		prev.PeerLinkIP = netip.Addr{}
		a.links[spec.Iface] = prev
	}

	addrs, _, err := a.readIface(ctx, spec.Iface)
	if err != nil {
		return fmt.Errorf("read %s: %w", spec.Iface, err)
	}
	aliasAdded, hostAdded := false, false
	fail := func(err error) error {
		if !had {
			if hostAdded {
				if rerr := a.hostRoutes.Remove(ctx, spec.PeerLinkIP, spec.Iface); rerr != nil {
					a.log.Warn("netd: rolling back a link's host route", "iface", spec.Iface, "err", rerr)
				}
			}
			if aliasAdded {
				if rerr := a.command(ctx, "ifconfig", spec.Iface, "-alias", spec.LinkIP.String()); rerr != nil {
					a.log.Warn("netd: rolling back a link's address", "iface", spec.Iface, "err", rerr)
				}
			}
		}
		return err
	}
	if !addrs[spec.LinkIP] {
		ip := spec.LinkIP.String()
		if err := a.command(ctx, "ifconfig", spec.Iface, "inet", ip, ip, "netmask", "255.255.255.255", "alias"); err != nil {
			return fail(fmt.Errorf("assign %s to %s: %w", ip, spec.Iface, err))
		}
		aliasAdded = true
	}
	if err := a.command(ctx, "ifconfig", spec.Iface, "-tso"); err != nil {
		a.log.Debug("netd: ifconfig -tso refused (the read-back decides)", "iface", spec.Iface, "err", err)
	}
	if err := a.command(ctx, "ifconfig", spec.Iface, "-lro"); err != nil {
		a.log.Debug("netd: ifconfig -lro refused (the read-back decides)", "iface", spec.Iface, "err", err)
	}
	if spec.PeerLinkIP.IsValid() {
		hostAdded = !(had && prev.PeerLinkIP == spec.PeerLinkIP)
		if err := a.hostRoutes.Ensure(ctx, spec.PeerLinkIP, spec.Iface); err != nil {
			return fail(fmt.Errorf("host route to %s on %s: %w", spec.PeerLinkIP, spec.Iface, err))
		}
	}
	addrs, opts, err := a.readIface(ctx, spec.Iface)
	if err != nil {
		return fail(fmt.Errorf("read back %s: %w", spec.Iface, err))
	}
	if !addrs[spec.LinkIP] {
		return fail(fmt.Errorf("%s does not carry %s after it was assigned", spec.Iface, spec.LinkIP))
	}
	var on []string
	for _, f := range offloadFlags {
		if opts[f] {
			on = append(on, f)
		}
	}
	if len(on) > 0 {
		return fail(fmt.Errorf("%s still has %s enabled after -tso/-lro", spec.Iface, strings.Join(on, ",")))
	}
	a.links[spec.Iface] = spec
	if aliasAdded || hostAdded || !had {
		a.log.Info("netd: direct link configured", "iface", spec.Iface, "linkIP", spec.LinkIP.String(), "peer", spec.PeerLinkIP.String())
	}
	return nil
}

// RemoveLink tears a direct-link port down, in the reverse order: the mesh's
// direct routes over it, then the host route they depended on, then the port's
// address, then its bridge0 membership is restored. An interface that has vanished
// has no address to remove and no membership to restore; that is success.
func (a *darwinApplier) RemoveLink(ctx context.Context, iface string) error {
	a.linkMu.Lock()
	defer a.linkMu.Unlock()
	spec, had := a.links[iface]
	if err := a.withdraw(ctx, iface); err != nil {
		return fmt.Errorf("withdraw the direct routes on %s: %w", iface, err)
	}
	if had && spec.PeerLinkIP.IsValid() {
		if err := a.hostRoutes.Remove(ctx, spec.PeerLinkIP, iface); err != nil {
			return fmt.Errorf("remove the host route to %s on %s: %w", spec.PeerLinkIP, iface, err)
		}
	}
	if had {
		if err := a.command(ctx, "ifconfig", iface, "-alias", spec.LinkIP.String()); err != nil {
			a.log.Debug("netd: ifconfig -alias tolerated (the address or interface may be gone)", "iface", iface, "err", err)
		}
		addrs, _, err := a.readIface(ctx, iface)
		if err == nil && addrs[spec.LinkIP] {
			return fmt.Errorf("%s still carries %s after its removal", iface, spec.LinkIP)
		}
	}
	a.restoreBridgeMember(ctx, iface)
	delete(a.links, iface)
	a.log.Info("netd: direct link removed", "iface", iface)
	return nil
}

// withdrawDirect removes the mesh device's direct routes over iface, if the mesh
// is up. It is the production a.withdraw.
func (a *darwinApplier) withdrawDirect(ctx context.Context, iface string) error {
	a.mu.Lock()
	dev := a.dev
	a.mu.Unlock()
	if dev == nil {
		return nil
	}
	_, err := dev.WithdrawIface(ctx, iface)
	return err
}

// removeBridgeMember takes iface out of bridge0 and reads the membership back.
func (a *darwinApplier) removeBridgeMember(ctx context.Context, iface string) error {
	members, ok := a.bridgeMembers(ctx)
	if !ok || !members[iface] {
		return nil
	}
	if err := a.command(ctx, "ifconfig", bridgeIface, "deletem", iface); err != nil {
		a.log.Debug("netd: ifconfig deletem refused (the read-back decides)", "iface", iface, "err", err)
	}
	if members, ok := a.bridgeMembers(ctx); ok && members[iface] {
		return fmt.Errorf("remove %s from %s: still a member after deletem", iface, bridgeIface)
	}
	a.log.Info("netd: removed a Thunderbolt port from the bridge", "iface", iface, "bridge", bridgeIface)
	return nil
}

// restoreBridgeMember puts iface back into bridge0. It is best-effort: no bridge,
// a vanished interface, or a refusal is logged, never an error, because a link
// that is gone must still be removable.
func (a *darwinApplier) restoreBridgeMember(ctx context.Context, iface string) {
	members, ok := a.bridgeMembers(ctx)
	if !ok || members[iface] {
		return
	}
	if _, _, err := a.readIface(ctx, iface); err != nil {
		a.log.Debug("netd: not restoring bridge membership of an absent interface", "iface", iface, "err", err)
		return
	}
	if err := a.command(ctx, "ifconfig", bridgeIface, "addm", iface); err != nil {
		a.log.Warn("netd: restoring a Thunderbolt port to the bridge", "iface", iface, "bridge", bridgeIface, "err", err)
		return
	}
	a.log.Info("netd: restored a Thunderbolt port to the bridge", "iface", iface, "bridge", bridgeIface)
}

// bridgeMembers reads bridge0's members; false when there is no bridge0.
func (a *darwinApplier) bridgeMembers(ctx context.Context) (map[string]bool, bool) {
	out, err := a.output(ctx, "ifconfig", bridgeIface)
	if err != nil {
		return nil, false
	}
	return parseBridgeMembers(out), true
}

// readIface reads an interface's IPv4 addresses and its option flags.
func (a *darwinApplier) readIface(ctx context.Context, iface string) (map[netip.Addr]bool, map[string]bool, error) {
	out, err := a.output(ctx, "ifconfig", iface)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s: %v", errNoSuchInterface, iface, err)
	}
	addrs, opts := parseIfconfig(out)
	return addrs, opts, nil
}

// reconcileLinksAtStart removes every interface address and every route in the
// reserved direct-link halves (netv1alpha1.IsLinkAddress): addresses first, then
// any host route to such an address and any route through one. A fresh daemon owns
// no link, so whatever it finds is a previous daemon's leftover (a crash between a
// ConfigureLink and its RemoveLink) or was never k3sm's to keep; the reserved
// halves are never self-assigned (RFC 3927 §2.1), so nothing else legitimately
// holds them. It is idempotent, and a failure is logged, never fatal: the daemon
// must start.
func (a *darwinApplier) reconcileLinksAtStart(ctx context.Context) {
	addrs, err := a.ifaceAddrs()
	if err != nil {
		a.log.Warn("netd: listing interface addresses for the direct-link sweep", "err", err)
	}
	ifaces := make([]string, 0, len(addrs))
	for name := range addrs {
		ifaces = append(ifaces, name)
	}
	sort.Strings(ifaces)
	for _, name := range ifaces {
		for _, ip := range addrs[name] {
			if !netv1alpha1.IsLinkAddress(ip) {
				continue
			}
			if err := a.command(ctx, "ifconfig", name, "-alias", ip.String()); err != nil {
				a.log.Warn("netd: removing a stale direct-link address", "iface", name, "ip", ip.String(), "err", err)
				continue
			}
			a.log.Info("netd: removed a stale direct-link address", "iface", name, "ip", ip.String())
		}
	}
	routes, err := a.hostRoutes.List(ctx)
	if err != nil {
		a.log.Warn("netd: listing routes for the direct-link sweep", "err", err)
		return
	}
	for _, r := range routes {
		if r.Interface == "" || !staleLinkRoute(r) {
			continue
		}
		if err := a.hostRoutes.Delete(ctx, r); err != nil {
			a.log.Warn("netd: removing a stale direct-link route", "route", r.String(), "err", err)
			continue
		}
		a.log.Info("netd: removed a stale direct-link route", "route", r.String())
	}
}

// staleLinkRoute reports whether r belongs to the reserved direct-link halves: a
// /32 to such an address that is not a gateway route, or any route through one.
func staleLinkRoute(r mesh.Route) bool {
	if r.Gateway.IsValid() {
		return netv1alpha1.IsLinkAddress(r.Gateway)
	}
	return r.Prefix.Bits() == 32 && netv1alpha1.IsLinkAddress(r.Prefix.Addr())
}

// parseIfconfig reads `ifconfig <iface>` output: the IPv4 addresses ("inet A
// netmask ...") and the option flags ("options=460<TSO4,TSO6,CHANNEL_IO>").
func parseIfconfig(out []byte) (map[netip.Addr]bool, map[string]bool) {
	addrs := make(map[netip.Addr]bool)
	opts := make(map[string]bool)
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		switch {
		case f[0] == "inet" && len(f) > 1:
			if ip, err := netip.ParseAddr(f[1]); err == nil {
				addrs[ip] = true
			}
		case strings.HasPrefix(f[0], "options="):
			lt, gt := strings.IndexByte(f[0], '<'), strings.LastIndexByte(f[0], '>')
			if lt < 0 || gt < lt {
				continue
			}
			for _, o := range strings.Split(f[0][lt+1:gt], ",") {
				if o != "" {
					opts[o] = true
				}
			}
		}
	}
	return addrs, opts
}

// parseBridgeMembers reads the "member: enX flags=..." lines of `ifconfig
// bridge0` output.
func parseBridgeMembers(out []byte) map[string]bool {
	members := make(map[string]bool)
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "member:" {
			members[f[1]] = true
		}
	}
	return members
}

// interfaceIPv4Addrs lists every interface's IPv4 addresses.
func interfaceIPv4Addrs() (map[string][]netip.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	out := make(map[string][]netip.Addr, len(ifaces))
	var errs []error
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			errs = append(errs, fmt.Errorf("addresses of %s: %w", ifi.Name, err))
			continue
		}
		for _, ad := range addrs {
			ipn, ok := ad.(*net.IPNet)
			if !ok {
				continue
			}
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Unmap().Is4() {
				out[ifi.Name] = append(out[ifi.Name], ip.Unmap())
			}
		}
	}
	return out, errors.Join(errs...)
}
