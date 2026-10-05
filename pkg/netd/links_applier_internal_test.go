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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"testing"

	"k3sm.io/darwin-net/pkg/mesh"
)

// fakeHost models the kernel state the link operations touch — bridge0's members,
// each interface's IPv4 addresses and option flags, and the host routes — and
// records every mutation in order. stuckMember, stuckTSO and noBridge reproduce a
// deletem that does not take, a driver that refuses -tso, and a host whose
// Thunderbolt Bridge was deleted.
type fakeHost struct {
	members     map[string]bool
	addrs       map[string]map[netip.Addr]bool
	opts        map[string]map[string]bool
	routes      []mesh.Route
	ops         []string
	stuckMember bool
	stuckTSO    bool
	noBridge    bool
}

func newFakeHost() *fakeHost {
	h := &fakeHost{
		members: map[string]bool{"en2": true, "en5": true, "en6": true},
		addrs:   map[string]map[netip.Addr]bool{},
		opts:    map[string]map[string]bool{},
	}
	for _, i := range []string{"en0", "en2", "en5", "en6"} {
		h.addrs[i] = map[netip.Addr]bool{}
		h.opts[i] = map[string]bool{"TSO4": true, "TSO6": true, "CHANNEL_IO": true}
	}
	return h
}

func (h *fakeHost) output(_ context.Context, name string, args ...string) ([]byte, error) {
	if name != "ifconfig" || len(args) != 1 {
		return nil, fmt.Errorf("unexpected read %s %v", name, args)
	}
	if args[0] == bridgeIface {
		if h.noBridge {
			return nil, errors.New("interface bridge0 does not exist")
		}
		var b strings.Builder
		b.WriteString("bridge0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n")
		var names []string
		for m := range h.members {
			names = append(names, m)
		}
		sort.Strings(names)
		for _, m := range names {
			fmt.Fprintf(&b, "\tmember: %s flags=3<LEARNING,DISCOVER>\n\t        ifmaxaddr 0 port 16 priority 0 path cost 0\n", m)
		}
		return []byte(b.String()), nil
	}
	addrs, ok := h.addrs[args[0]]
	if !ok {
		return nil, fmt.Errorf("interface %s does not exist", args[0])
	}
	var opts []string
	for o := range h.opts[args[0]] {
		opts = append(opts, o)
	}
	sort.Strings(opts)
	var b strings.Builder
	fmt.Fprintf(&b, "%s: flags=8963<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\toptions=460<%s>\n", args[0], strings.Join(opts, ","))
	for a := range addrs {
		fmt.Fprintf(&b, "\tinet %s netmask 0xffffffff\n", a)
	}
	b.WriteString("\tstatus: active\n")
	return []byte(b.String()), nil
}

func (h *fakeHost) command(_ context.Context, name string, args ...string) error {
	h.ops = append(h.ops, name+" "+strings.Join(args, " "))
	if name != "ifconfig" || len(args) < 2 {
		return fmt.Errorf("unexpected command %s %v", name, args)
	}
	iface := args[0]
	switch {
	case iface == bridgeIface && args[1] == "deletem":
		if !h.stuckMember {
			delete(h.members, args[2])
		}
	case iface == bridgeIface && args[1] == "addm":
		h.members[args[2]] = true
	case args[1] == "inet":
		h.addrs[iface][netip.MustParseAddr(args[2])] = true
	case args[1] == "-alias":
		if _, ok := h.addrs[iface]; !ok {
			return fmt.Errorf("interface %s does not exist", iface)
		}
		delete(h.addrs[iface], netip.MustParseAddr(args[2]))
	case args[1] == "-tso":
		if !h.stuckTSO {
			delete(h.opts[iface], "TSO4")
			delete(h.opts[iface], "TSO6")
		}
	case args[1] == "-lro":
		return fmt.Errorf("%s does not support -lro", iface)
	}
	return nil
}

func (h *fakeHost) Ensure(_ context.Context, peer netip.Addr, iface string) error {
	h.ops = append(h.ops, fmt.Sprintf("route add -host %s -interface %s", peer, iface))
	h.routes = append(h.routes, mesh.Route{Prefix: netip.PrefixFrom(peer, 32), Interface: iface})
	return nil
}

func (h *fakeHost) Remove(_ context.Context, peer netip.Addr, iface string) error {
	return h.Delete(context.Background(), mesh.Route{Prefix: netip.PrefixFrom(peer, 32), Interface: iface})
}

func (h *fakeHost) List(context.Context) ([]mesh.Route, error) {
	return slices.Clone(h.routes), nil
}

func (h *fakeHost) Delete(_ context.Context, r mesh.Route) error {
	h.ops = append(h.ops, "route delete "+r.String())
	h.routes = slices.DeleteFunc(h.routes, func(k mesh.Route) bool { return k == r })
	return nil
}

func linkApplier(h *fakeHost) *darwinApplier {
	a := newDarwinApplier(linkSelf, slog.New(slog.DiscardHandler))
	a.command = h.command
	a.output = h.output
	a.hostRoutes = h
	a.withdraw = func(_ context.Context, iface string) error {
		h.ops = append(h.ops, "withdraw direct routes on "+iface)
		return nil
	}
	a.ifaceAddrs = func() (map[string][]netip.Addr, error) {
		out := map[string][]netip.Addr{}
		for i, set := range h.addrs {
			for a := range set {
				out[i] = append(out[i], a)
			}
		}
		return out, nil
	}
	return a
}

// opIndex returns the position of the first op starting with prefix.
func opIndex(t *testing.T, ops []string, prefix string) int {
	t.Helper()
	for i, o := range ops {
		if strings.HasPrefix(o, prefix) {
			return i
		}
	}
	t.Fatalf("no operation %q in %v", prefix, ops)
	return -1
}

// TestApplierConfigureLinkOrderAndReadBack pins the ConfigureLink sequence on the
// executor: the Thunderbolt member leaves bridge0 (and only it), then the /32
// alias, offload off, the on-link host route; and success is reported only once
// the read-back shows the alias present and TSO4/TSO6/LRO absent. A driver that
// refuses -lro but never had LRO is fine; the bridge itself is never downed.
func TestApplierConfigureLinkOrderAndReadBack(t *testing.T) {
	h := newFakeHost()
	a := linkApplier(h)
	spec := LinkSpec{Iface: "en5", LinkIP: linkIP(t, 0, 3), PeerLinkIP: linkIP(t, 1, 0)}
	if err := a.ConfigureLink(context.Background(), spec); err != nil {
		t.Fatalf("ConfigureLink: %v", err)
	}
	deletem := opIndex(t, h.ops, "ifconfig bridge0 deletem en5")
	alias := opIndex(t, h.ops, "ifconfig en5 inet "+spec.LinkIP.String()+" "+spec.LinkIP.String()+" netmask 255.255.255.255 alias")
	tso := opIndex(t, h.ops, "ifconfig en5 -tso")
	host := opIndex(t, h.ops, "route add -host "+spec.PeerLinkIP.String()+" -interface en5")
	if !(deletem < alias && alias < tso && tso < host) {
		t.Fatalf("order = %v, want deletem < alias < -tso < host route", h.ops)
	}
	for _, o := range h.ops {
		if strings.HasPrefix(o, "ifconfig bridge0 down") || strings.Contains(o, "deletem en2") || strings.Contains(o, "deletem en6") {
			t.Fatalf("touched the bridge beyond this port's membership: %q", o)
		}
	}
	if h.members["en5"] || !h.members["en2"] {
		t.Fatalf("members = %v, want en5 out and the others untouched", h.members)
	}

	// Idempotent: a re-assertion changes nothing in the kernel.
	h.ops = nil
	if err := a.ConfigureLink(context.Background(), spec); err != nil {
		t.Fatalf("re-assert: %v", err)
	}
	for _, o := range h.ops {
		if strings.Contains(o, " inet ") || strings.Contains(o, "deletem") {
			t.Fatalf("a re-assertion re-plumbed the link: %v", h.ops)
		}
	}

	// configd put the port back into the bridge: the next ConfigureLink re-removes it.
	h.members["en5"] = true
	if err := a.ConfigureLink(context.Background(), spec); err != nil {
		t.Fatalf("re-assert after re-add: %v", err)
	}
	if h.members["en5"] {
		t.Fatal("a re-added member was not removed again")
	}
}

// TestApplierConfigureLinkNeverHalfConfigured pins the failure paths: a member
// removal that does not take leaves no alias behind (nothing else ran), and an
// offload read-back failure rolls the fresh alias and host route back. No bridge0
// at all is not an error.
func TestApplierConfigureLinkNeverHalfConfigured(t *testing.T) {
	spec := LinkSpec{Iface: "en5", LinkIP: linkIP(t, 0, 3), PeerLinkIP: linkIP(t, 1, 0)}

	h := newFakeHost()
	h.stuckMember = true
	if err := linkApplier(h).ConfigureLink(context.Background(), spec); err == nil {
		t.Fatal("ConfigureLink reported success with the port still in the bridge")
	}
	if len(h.addrs["en5"]) != 0 || len(h.routes) != 0 {
		t.Fatalf("a failed member removal left state behind: addrs %v routes %v", h.addrs["en5"], h.routes)
	}

	h = newFakeHost()
	h.stuckTSO = true
	if err := linkApplier(h).ConfigureLink(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "TSO4") {
		t.Fatalf("ConfigureLink error = %v, want the offload read-back to refuse", err)
	}
	if len(h.addrs["en5"]) != 0 || len(h.routes) != 0 {
		t.Fatalf("a failed read-back left a half-configured link: addrs %v routes %v", h.addrs["en5"], h.routes)
	}

	h = newFakeHost()
	h.noBridge = true
	if err := linkApplier(h).ConfigureLink(context.Background(), spec); err != nil {
		t.Fatalf("a host without bridge0 refused the link: %v", err)
	}
}

// TestApplierRemoveLinkWithdrawsFirst pins the down order on the executor: the
// mesh's direct routes over the cable go, then the host route they depend on, then
// the address, then the bridge membership is restored. A re-pointed cable
// withdraws through the old peer before its host route goes and the new one comes.
func TestApplierRemoveLinkWithdrawsFirst(t *testing.T) {
	h := newFakeHost()
	a := linkApplier(h)
	ctx := context.Background()
	spec := LinkSpec{Iface: "en5", LinkIP: linkIP(t, 0, 3), PeerLinkIP: linkIP(t, 1, 0)}
	if err := a.ConfigureLink(ctx, spec); err != nil {
		t.Fatal(err)
	}

	h.ops = nil
	moved := spec
	moved.PeerLinkIP = linkIP(t, 2, 0)
	if err := a.ConfigureLink(ctx, moved); err != nil {
		t.Fatal(err)
	}
	w := opIndex(t, h.ops, "withdraw direct routes on en5")
	oldHost := opIndex(t, h.ops, "route delete "+spec.PeerLinkIP.String()+"/32")
	newHost := opIndex(t, h.ops, "route add -host "+moved.PeerLinkIP.String())
	if !(w < oldHost && oldHost < newHost) {
		t.Fatalf("re-point order = %v, want withdraw < old host route delete < new host route", h.ops)
	}

	h.ops = nil
	if err := a.RemoveLink(ctx, "en5"); err != nil {
		t.Fatal(err)
	}
	w = opIndex(t, h.ops, "withdraw direct routes on en5")
	host := opIndex(t, h.ops, "route delete "+moved.PeerLinkIP.String()+"/32")
	alias := opIndex(t, h.ops, "ifconfig en5 -alias")
	addm := opIndex(t, h.ops, "ifconfig bridge0 addm en5")
	if !(w < host && host < alias && alias < addm) {
		t.Fatalf("remove order = %v, want withdraw < host route < alias < addm", h.ops)
	}
	if len(h.addrs["en5"]) != 0 || len(h.routes) != 0 || !h.members["en5"] {
		t.Fatalf("after RemoveLink: addrs %v routes %v member %v", h.addrs["en5"], h.routes, h.members["en5"])
	}

	// A vanished interface is still removable.
	if err := a.ConfigureLink(ctx, LinkSpec{Iface: "en6", LinkIP: linkIP(t, 0, 4)}); err != nil {
		t.Fatal(err)
	}
	delete(h.addrs, "en6")
	if err := a.RemoveLink(ctx, "en6"); err != nil {
		t.Fatalf("RemoveLink of a vanished interface: %v", err)
	}
}

// TestApplierStartupSweepsReservedHalves pins the start-up reconcile: every
// address and route in the reserved direct-link halves is removed; a self-assigned
// link-local address, a LAN address and an unrelated route are left alone.
func TestApplierStartupSweepsReservedHalves(t *testing.T) {
	h := newFakeHost()
	stale := linkIP(t, 0, 3)
	h.addrs["en5"][stale] = true
	h.addrs["en0"][netip.MustParseAddr("169.254.33.7")] = true
	h.addrs["en0"][netip.MustParseAddr("192.168.1.5")] = true
	h.routes = []mesh.Route{
		{Prefix: netip.PrefixFrom(linkIP(t, 1, 0), 32), Interface: "en5"},
		{Prefix: netip.MustParsePrefix("100.64.1.0/25"), Interface: "en5", Gateway: linkIP(t, 1, 0)},
		{Prefix: netip.MustParsePrefix("100.64.1.0/24"), Interface: "utun4"},
		{Prefix: netip.MustParsePrefix("169.254.0.0/16"), Interface: "en0"},
	}
	linkApplier(h).reconcileLinksAtStart(context.Background())
	if h.addrs["en5"][stale] {
		t.Error("a stale reserved-half address survived")
	}
	if !h.addrs["en0"][netip.MustParseAddr("169.254.33.7")] || !h.addrs["en0"][netip.MustParseAddr("192.168.1.5")] {
		t.Errorf("an address outside the reserved halves was removed: %v", h.addrs["en0"])
	}
	want := []mesh.Route{
		{Prefix: netip.MustParsePrefix("100.64.1.0/24"), Interface: "utun4"},
		{Prefix: netip.MustParsePrefix("169.254.0.0/16"), Interface: "en0"},
	}
	if !slices.Equal(h.routes, want) {
		t.Errorf("routes after the sweep = %v, want %v", h.routes, want)
	}
}

// TestParseIfconfigAndBridge pins the two ifconfig parsers on the real format.
func TestParseIfconfigAndBridge(t *testing.T) {
	addrs, opts := parseIfconfig([]byte("en2: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500\n\toptions=460<TSO4,TSO6,CHANNEL_IO>\n\tether 02:00:00:00:00:40\n\tinet 169.254.0.4 netmask 0xffffffff\n\tmedia: autoselect <full-duplex>\n\tstatus: inactive\n"))
	if !addrs[netip.MustParseAddr("169.254.0.4")] || len(addrs) != 1 {
		t.Errorf("addrs = %v", addrs)
	}
	if !opts["TSO4"] || !opts["TSO6"] || !opts["CHANNEL_IO"] || len(opts) != 3 {
		t.Errorf("opts = %v", opts)
	}
	members := parseBridgeMembers([]byte("bridge0: flags=8863<UP> mtu 1500\n\tmember: en2 flags=3<LEARNING,DISCOVER>\n\t        ifmaxaddr 0 port 16 priority 0 path cost 0\n\tmember: en3 flags=3<LEARNING,DISCOVER>\n\tstatus: inactive\n"))
	if !members["en2"] || !members["en3"] || len(members) != 2 {
		t.Errorf("members = %v", members)
	}
}
