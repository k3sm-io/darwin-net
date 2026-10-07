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
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"

	netv1 "k3sm.io/apis/net/v1"
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/linkwatch"
)

// The fixture cluster: this node holds index 0 (100.64.0.0/24), the peer index 1
// (100.64.1.0/24). The peer's port 0 is cabled to this node's en5.
var (
	selfCIDR     = netip.MustParsePrefix("100.64.0.0/24")
	peerCIDR     = netip.MustParsePrefix("100.64.1.0/24")
	peerLinkIP   = mustLinkIP(1, 0)
	selfLinkIP   = mustLinkIP(0, 3)
	peerLow      = netip.MustParsePrefix("100.64.1.0/25")
	peerHigh     = netip.MustParsePrefix("100.64.1.128/25")
	peerUnderlay = "192.0.2.10:51820"
	peerDirect   = netip.AddrPortFrom(mustLinkIP(1, 0), 51820).String()
)

func mustLinkIP(idx, port int) netip.Addr {
	a, err := netv1alpha1.LinkIP(idx, port)
	if err != nil {
		panic(err)
	}
	return a
}

// directPeerSpec is the peer as a post-M17 writer publishes it: Endpoint carries
// the underlay, Endpoints lists the underlay and the direct candidates.
func directPeerSpec() netv1.MeshPeerSpec {
	s := peerSpec("nodeB", peerCIDR.String(), peerUnderlay, 0x42)
	s.Endpoints = []netv1.EndpointCandidate{
		{Address: peerUnderlay, Link: netv1.EndpointLinkUnderlay},
		{Address: peerDirect, Link: netv1.EndpointLinkDirect},
	}
	return s
}

// upStatus is this node's resolved status with en5 up toward nodeB.
func upStatus() netv1alpha1.DirectLinkStatus {
	return netv1alpha1.DirectLinkStatus{Ports: []netv1alpha1.DirectLinkPortStatus{{
		Iface: "en5", PeerNodeName: "nodeB", PeerIface: "en2", PeerLinkIP: peerLinkIP.String(), State: netv1alpha1.DirectLinkStateUp,
	}}}
}

// TestRouteOverrideNeverBlackholes pins the route ordering of R14 over one fake
// routing socket shared by the helper's host-route code and the mesh device: up =
// the on-link host route, then the two /25s; down = the /25s, then the host route;
// and the peer's utun /24 is never deleted while the peer exists. Both down paths
// are exercised: the reconcile dropping the direct peer, and the helper
// withdrawing the cable (RemoveLink). The kernel property — that the kernel
// deletes the interface-bound routes on unplug and traffic falls to the /24 — is
// the lab rung, not this test.
func TestRouteOverrideNeverBlackholes(t *testing.T) {
	for _, down := range []string{"reconcile drops the direct peer", "helper withdraws the cable"} {
		t.Run(down, func(t *testing.T) {
			fake := &fakeRouteTable{}
			dev := routeDevice(fake)
			dev.cfg.meshIP = netip.MustParseAddr("100.64.0.1")
			host := &HostRoutes{rt: fake}
			ctx := context.Background()

			utun := RouteSpec{Prefix: peerCIDR}
			direct := []RouteSpec{utun,
				{Prefix: peerLow, Iface: "en5", Gateway: peerLinkIP},
				{Prefix: peerHigh, Iface: "en5", Gateway: peerLinkIP}}

			if _, err := dev.reconcileRoutes(ctx, []RouteSpec{utun}); err != nil {
				t.Fatalf("tunnel-only reconcile: %v", err)
			}
			if err := host.Ensure(ctx, peerLinkIP, "en5"); err != nil { // ConfigureLink
				t.Fatalf("host route: %v", err)
			}
			if _, err := dev.reconcileRoutes(ctx, direct); err != nil {
				t.Fatalf("direct reconcile: %v", err)
			}
			for _, r := range fake.adds {
				if r.Gateway.IsValid() && r.Source != dev.cfg.meshIP {
					t.Errorf("direct route %s carries source %v, want the mesh-egress address %s (RTAX_IFA)", r, r.Source, dev.cfg.meshIP)
				}
			}
			if down == "reconcile drops the direct peer" {
				if _, err := dev.reconcileRoutes(ctx, []RouteSpec{utun}); err != nil {
					t.Fatalf("fallback reconcile: %v", err)
				}
			} else if _, err := dev.WithdrawIface(ctx, "en5"); err != nil {
				t.Fatalf("withdraw: %v", err)
			}
			if err := host.Remove(ctx, peerLinkIP, "en5"); err != nil { // RemoveLink
				t.Fatalf("remove host route: %v", err)
			}

			idx := func(op string) int {
				for i, o := range fake.ops {
					if o == op {
						return i
					}
				}
				t.Fatalf("operation %q never happened; ops: %v", op, fake.ops)
				return -1
			}
			hostRoute := hostRoute(peerLinkIP, "en5").String()
			lowRoute := Route{Prefix: peerLow, Interface: "en5", Gateway: peerLinkIP}.String()
			highRoute := Route{Prefix: peerHigh, Interface: "en5", Gateway: peerLinkIP}.String()
			addHost, delHost := idx("add "+hostRoute), idx("delete "+hostRoute)
			for _, r := range []string{lowRoute, highRoute} {
				if add := idx("add " + r); add < addHost {
					t.Errorf("up: %s added before the host route it depends on; ops: %v", r, fake.ops)
				}
				if del := idx("delete " + r); del > delHost {
					t.Errorf("down: %s deleted after the host route it depends on; ops: %v", r, fake.ops)
				}
			}
			for _, o := range fake.ops {
				if o == "delete "+(Route{Prefix: peerCIDR, Interface: "utun9"}).String() {
					t.Fatalf("the peer's utun /24 was deleted; ops: %v", fake.ops)
				}
			}
			if _, ok := dev.routes[peerCIDR]; !ok {
				t.Errorf("the device no longer owns the utun /24: %v", dev.routes)
			}
		})
	}
}

// TestReconcileRoutesComparesGatewayAndFlags pins the extended read-back: a /25
// the kernel holds through a different gateway, or as a link route rather than a
// gateway route, is not the route the plan wants.
func TestReconcileRoutesComparesGatewayAndFlags(t *testing.T) {
	want := RouteSpec{Prefix: peerLow, Iface: "en5", Gateway: peerLinkIP}
	for _, tc := range []struct {
		name string
		k    Route
	}{
		{"another gateway", Route{Prefix: peerLow, Interface: "en5", Gateway: mustLinkIP(2, 0), Flags: unix.RTF_UP | unix.RTF_GATEWAY}},
		{"a link route", Route{Prefix: peerLow, Interface: "en5", Flags: unix.RTF_UP}},
		{"another interface", Route{Prefix: peerLow, Interface: "en6", Gateway: peerLinkIP, Flags: unix.RTF_UP | unix.RTF_GATEWAY}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeRouteTable{dropAdds: true, table: []Route{tc.k}}
			d := routeDevice(fake)
			if _, err := d.reconcileRoutes(context.Background(), []RouteSpec{want}); !errors.Is(err, ErrRouteNotInstalled) {
				t.Fatalf("error = %v, want ErrRouteNotInstalled", err)
			}
		})
	}
	// The utun /24 must likewise not be satisfied by a gateway route.
	fake := &fakeRouteTable{dropAdds: true, table: []Route{{Prefix: peerCIDR, Interface: "utun9", Gateway: peerLinkIP, Flags: unix.RTF_UP | unix.RTF_GATEWAY}}}
	if _, err := routeDevice(fake).reconcileRoutes(context.Background(), []RouteSpec{{Prefix: peerCIDR}}); !errors.Is(err, ErrRouteNotInstalled) {
		t.Fatalf("a gateway route satisfied the utun link route: %v", err)
	}
}

// TestRouteMessageEncodesGatewayAndHostRoutes pins the two new request forms
// against the parser the read-back uses.
func TestRouteMessageEncodesGatewayAndHostRoutes(t *testing.T) {
	src := netip.MustParseAddr("100.64.0.1")
	parse := func(t *testing.T, m *xroute.RouteMessage) *xroute.RouteMessage {
		t.Helper()
		b, err := m.Marshal()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		msgs, err := xroute.ParseRIB(xroute.RIBTypeRoute, b)
		if err != nil || len(msgs) != 1 {
			t.Fatalf("parse: %v (%d)", err, len(msgs))
		}
		rm := msgs[0].(*xroute.RouteMessage)
		// A request carries no rtm_index; the kernel's dump of the installed route
		// does. Stamp it as the dump would, so decodeRoute names the interface.
		rm.Index = 12
		return rm
	}
	t.Run("gateway /25 with source", func(t *testing.T) {
		rm := parse(t, routeMessage(unix.RTM_ADD, Route{Prefix: peerHigh, Interface: "en5", Gateway: peerLinkIP, Source: src}, 12))
		if rm.Flags != unix.RTF_UP|unix.RTF_STATIC|unix.RTF_GATEWAY {
			t.Errorf("flags = %#x, want RTF_UP|RTF_STATIC|RTF_GATEWAY", rm.Flags)
		}
		gw, ok := rm.Addrs[unix.RTAX_GATEWAY].(*xroute.Inet4Addr)
		if !ok || netip.AddrFrom4(gw.IP) != peerLinkIP {
			t.Errorf("gateway = %+v, want %s", rm.Addrs[unix.RTAX_GATEWAY], peerLinkIP)
		}
		ifp, ok := rm.Addrs[unix.RTAX_IFP].(*xroute.LinkAddr)
		if !ok || ifp.Index != 12 {
			t.Errorf("ifp = %+v, want the AF_LINK address of index 12", rm.Addrs[unix.RTAX_IFP])
		}
		ifa, ok := rm.Addrs[unix.RTAX_IFA].(*xroute.Inet4Addr)
		if !ok || netip.AddrFrom4(ifa.IP) != src {
			t.Errorf("ifa = %+v, want %s", rm.Addrs[unix.RTAX_IFA], src)
		}
		r, ok := decodeRoute(rm, map[int]string{12: "en5"})
		if !ok || !holds(r, Route{Prefix: peerHigh, Interface: "en5", Gateway: peerLinkIP}) {
			t.Errorf("read-back decodes %+v (%v), which does not hold the route it was built from", r, ok)
		}
	})
	t.Run("on-link host route", func(t *testing.T) {
		rm := parse(t, routeMessage(unix.RTM_ADD, Route{Prefix: netip.PrefixFrom(peerLinkIP, 32), Interface: "en5"}, 12))
		if rm.Flags != unix.RTF_UP|unix.RTF_STATIC|unix.RTF_HOST {
			t.Errorf("flags = %#x, want RTF_UP|RTF_STATIC|RTF_HOST", rm.Flags)
		}
		if gw, ok := rm.Addrs[unix.RTAX_GATEWAY].(*xroute.LinkAddr); !ok || gw.Index != 12 {
			t.Errorf("gateway = %+v, want the AF_LINK address of index 12", rm.Addrs[unix.RTAX_GATEWAY])
		}
		r, ok := decodeRoute(rm, map[int]string{12: "en5"})
		if !ok || !holds(r, hostRoute(peerLinkIP, "en5")) {
			t.Errorf("read-back decodes %+v (%v)", r, ok)
		}
	})
}

// TestDirectRouteRequiresPeerRouteReady pins R13: no /25s unless the resolver
// reports the peer's port up (both ends routeReady), the link is up locally, and
// the probe hears the peer — and, through the controller, unless this node
// configured the link. Each failing input alone withholds the route.
func TestDirectRouteRequiresPeerRouteReady(t *testing.T) {
	up := func(string) bool { return true }
	down := func(string) bool { return false }
	alive := func(string, netip.Addr) bool { return true }
	dead := func(string, netip.Addr) bool { return false }
	withPort := func(f func(*netv1alpha1.DirectLinkPortStatus)) netv1alpha1.DirectLinkStatus {
		s := upStatus()
		f(&s.Ports[0])
		return s
	}
	cases := []struct {
		name    string
		status  netv1alpha1.DirectLinkStatus
		localUp func(string) bool
		probe   func(string, netip.Addr) bool
		want    bool
	}{
		{"everything agrees", upStatus(), up, alive, true},
		{"port down in status", withPort(func(p *netv1alpha1.DirectLinkPortStatus) { p.State = netv1alpha1.DirectLinkStateDown }), up, alive, false},
		{"peer unknown", withPort(func(p *netv1alpha1.DirectLinkPortStatus) { p.State = netv1alpha1.DirectLinkStatePeerUnknown }), up, alive, false},
		{"no peer link address yet", withPort(func(p *netv1alpha1.DirectLinkPortStatus) { p.PeerLinkIP = "" }), up, alive, false},
		{"peer address outside the reserved halves", withPort(func(p *netv1alpha1.DirectLinkPortStatus) { p.PeerLinkIP = "169.254.7.7" }), up, alive, false},
		{"no peer node", withPort(func(p *netv1alpha1.DirectLinkPortStatus) { p.PeerNodeName = "" }), up, alive, false},
		{"link down locally", upStatus(), down, alive, false},
		{"probe dead", upStatus(), up, dead, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EligibleDirectRoutes(tc.status, tc.localUp, tc.probe)
			want := DirectRoutes{}
			if tc.want {
				want["nodeB"] = DirectRoute{Iface: "en5", Gateway: peerLinkIP}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("EligibleDirectRoutes = %v, want %v", got, want)
			}
		})
	}

	// Through the controller: the plan gains the /25s only once every input is in.
	ctx := context.Background()
	dev := &fakeLinkDevice{}
	ping := &scriptedPinger{}
	m, err := New(selfCIDR, withDevice(dev), withPinger(ping), WithLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	peers := []netv1.MeshPeerSpec{directPeerSpec()}
	directCount := func() int {
		t.Helper()
		if err := m.Reconcile(ctx, peers); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		n := 0
		for _, r := range dev.last().Routes {
			if r.Direct() {
				n++
			}
		}
		return n
	}
	m.SetDirectLinkStatus(upStatus())
	m.HandleLinkEvent(ctx, linkwatch.Event{Iface: "en5", Up: true})
	ping.set(nil)
	m.prober.round(ctx)
	if n := directCount(); n != 0 {
		t.Fatalf("direct routes = %d before this node configured the link, want 0", n)
	}
	if _, err := m.ConfigureLink(ctx, LinkConfig{Iface: "en5", PortOrdinal: 3, LinkIP: selfLinkIP}); err != nil {
		t.Fatalf("ConfigureLink: %v", err)
	}
	if n := directCount(); n != 0 {
		t.Fatalf("direct routes = %d before the probe heard the peer (a new target starts dead), want 0", n)
	}
	m.prober.round(ctx)
	if n := directCount(); n != 2 {
		t.Fatalf("direct routes = %d with every input in, want 2", n)
	}
	if got := dev.lastLink(); got.PeerLinkIP != peerLinkIP {
		t.Errorf("the reconcile re-confirmed the link with peer %v, want %s", got.PeerLinkIP, peerLinkIP)
	}
	m.HandleLinkEvent(ctx, linkwatch.Event{Iface: "en5"})
	if n := directCount(); n != 0 {
		t.Fatalf("direct routes = %d after the link went down locally, want 0", n)
	}
}

// TestOldReaderAcceptsEndpointsField pins R12 from the reader side: a MeshPeer
// carrying the additive endpoints list builds exactly the plan it would without
// it when no direct route is eligible (Endpoint carries the underlay); a
// cable-only peer whose Endpoint is a reserved-half address is accepted, not
// skipped; and a candidate with a Link this reader does not know is ignored
// rather than skipping the peer.
func TestOldReaderAcceptsEndpointsField(t *testing.T) {
	legacy := peerSpec("nodeB", peerCIDR.String(), peerUnderlay, 0x42)
	cableOnly := peerSpec("nodeC", "100.64.2.0/24", netip.AddrPortFrom(mustLinkIP(2, 1), 51820).String(), 0x43)
	cableOnly.Endpoints = []netv1.EndpointCandidate{{Address: cableOnly.Endpoint, Link: netv1.EndpointLinkDirect}}
	future := directPeerSpec()
	future.Endpoints = append(future.Endpoints, netv1.EndpointCandidate{Address: "203.0.113.9:51820", Link: "satellite"})

	before, err := BuildPlan(selfCIDR, []netv1.MeshPeerSpec{legacy}, nil)
	if err != nil {
		t.Fatal(err)
	}
	after, err := BuildPlan(selfCIDR, []netv1.MeshPeerSpec{directPeerSpec()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("a peer carrying endpoints built a different plan with no direct route eligible:\n before %+v\n after  %+v", before, after)
	}
	plan, err := BuildPlan(selfCIDR, []netv1.MeshPeerSpec{future, cableOnly}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Skipped) != 0 {
		t.Fatalf("peers skipped: %+v", plan.Skipped)
	}
	if len(plan.Peers) != 2 || plan.Peers[0].Endpoint != peerUnderlay || plan.Peers[1].Endpoint != cableOnly.Endpoint {
		t.Fatalf("peers = %+v", plan.Peers)
	}
	if _, err := ValidatePlan(selfCIDR, []netv1.MeshPeerSpec{cableOnly}, nil); err != nil {
		t.Errorf("the strict form refused a reserved-half Endpoint: %v", err)
	}
}

// TestSelectEndpointCandidates pins the candidate choice per peer.
func TestSelectEndpointCandidates(t *testing.T) {
	route := DirectRoute{Iface: "en5", Gateway: peerLinkIP}
	otherDirect := netip.AddrPortFrom(mustLinkIP(1, 1), 51820).String()
	cases := []struct {
		name   string
		cands  []netv1.EndpointCandidate
		direct bool
		want   string
	}{
		{"direct route, matching direct candidate", directPeerSpec().Endpoints, true, peerDirect},
		{"no direct route: first underlay", directPeerSpec().Endpoints, false, peerUnderlay},
		{"direct route, direct candidate on another cable", []netv1.EndpointCandidate{{Address: otherDirect, Link: netv1.EndpointLinkDirect}, {Address: peerUnderlay, Link: netv1.EndpointLinkUnderlay}}, true, peerUnderlay},
		{"no candidates: Endpoint", nil, true, "198.51.100.7:51820"},
		{"only a direct candidate, no route: Endpoint", []netv1.EndpointCandidate{{Address: peerDirect, Link: netv1.EndpointLinkDirect}}, false, "198.51.100.7:51820"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := peerSpec("nodeB", peerCIDR.String(), "198.51.100.7:51820", 0x42)
			spec.Endpoints = tc.cands
			if got := selectEndpoint(spec, route, tc.direct); got != tc.want {
				t.Errorf("selectEndpoint = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBuildPlanDirectRoutes pins the plan shape for a direct peer: the utun /24
// stays, the two /25s go through the gateway on the cable, and the endpoint is
// the matching direct candidate.
func TestBuildPlanDirectRoutes(t *testing.T) {
	other := peerSpec("nodeC", "100.64.2.0/24", "192.0.2.11:51820", 0x43)
	plan, err := BuildPlan(selfCIDR, []netv1.MeshPeerSpec{directPeerSpec(), other},
		DirectRoutes{"nodeB": {Iface: "en5", Gateway: peerLinkIP}, "ghost": {Iface: "en6", Gateway: mustLinkIP(9, 0)}})
	if err != nil {
		t.Fatal(err)
	}
	want := []RouteSpec{
		{Prefix: peerCIDR},
		{Prefix: peerLow, Iface: "en5", Gateway: peerLinkIP},
		{Prefix: peerHigh, Iface: "en5", Gateway: peerLinkIP},
		{Prefix: netip.MustParsePrefix("100.64.2.0/24")},
	}
	if !reflect.DeepEqual(plan.Routes, want) {
		t.Fatalf("routes = %v, want %v", plan.Routes, want)
	}
	if plan.Peers[0].Endpoint != peerDirect || plan.Peers[1].Endpoint != "192.0.2.11:51820" {
		t.Fatalf("endpoints = %q, %q", plan.Peers[0].Endpoint, plan.Peers[1].Endpoint)
	}
	if len(plan.Direct) != 1 || plan.Direct[0].PodCIDR != peerCIDR {
		t.Fatalf("direct = %+v", plan.Direct)
	}
	if len(plan.DirectRejected) != 1 || plan.DirectRejected[0].NodeName != "ghost" {
		t.Fatalf("a direct route for no peer must be recorded, got %+v", plan.DirectRejected)
	}
}

// TestValidatePlanRequiresReservedGateways pins the strict form's direct checks.
func TestValidatePlanRequiresReservedGateways(t *testing.T) {
	peers := []netv1.MeshPeerSpec{directPeerSpec()}
	for _, tc := range []struct {
		name   string
		direct DirectRoutes
	}{
		{"gateway on the LAN", DirectRoutes{"nodeB": {Iface: "en5", Gateway: netip.MustParseAddr("192.168.1.20")}}},
		{"self-assigned link-local gateway", DirectRoutes{"nodeB": {Iface: "en5", Gateway: netip.MustParseAddr("169.254.7.7")}}},
		{"not an Ethernet interface", DirectRoutes{"nodeB": {Iface: "utun3", Gateway: peerLinkIP}}},
		{"no interface", DirectRoutes{"nodeB": {Gateway: peerLinkIP}}},
		{"no such peer", DirectRoutes{"nodeZ": {Iface: "en5", Gateway: peerLinkIP}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ValidatePlan(selfCIDR, peers, tc.direct); !errors.Is(err, ErrDirectRoute) {
				t.Fatalf("error = %v, want ErrDirectRoute", err)
			}
		})
	}
	if _, err := ValidatePlan(selfCIDR, peers, DirectRoutes{"nodeB": {Iface: "en5", Gateway: peerLinkIP}}); err != nil {
		t.Fatalf("a well-formed direct route was refused: %v", err)
	}
}

// TestDirectPathDeathReprogramsEndpoint pins that the roaming contract re-stamps
// an endpoint when the SELECTED candidate changes: the device last programmed the
// direct address, the cable died, and the next plan selects the underlay. A peer
// whose CR endpoint did not change would otherwise keep a dead address, since
// wireguard-go roams only on a received packet.
func TestDirectPathDeathReprogramsEndpoint(t *testing.T) {
	onCable, err := BuildPlan(selfCIDR, []netv1.MeshPeerSpec{directPeerSpec()}, DirectRoutes{"nodeB": {Iface: "en5", Gateway: peerLinkIP}})
	if err != nil {
		t.Fatal(err)
	}
	_, mem := onCable.UAPIUpdate(nil)
	offCable, err := BuildPlan(selfCIDR, []netv1.MeshPeerSpec{directPeerSpec()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	uapi, _ := offCable.UAPIUpdate(mem)
	if !strings.Contains(uapi, "endpoint="+peerUnderlay+"\n") {
		t.Fatalf("the update after the cable died does not re-program the underlay endpoint:\n%s", uapi)
	}
	again, _ := offCable.UAPIUpdate(map[string]string{offCable.Peers[0].PublicKeyHex: peerUnderlay})
	if strings.Contains(again, "endpoint=") {
		t.Fatalf("an unchanged selection re-stamped the endpoint (the roaming contract):\n%s", again)
	}
}

// TestProberDeclaresDeathAfterThreeMisses pins the liveness probe: a new target is
// dead until it answers, it stays alive through two misses, the third declares it
// dead (one callback), and an answer brings it back (one callback).
func TestProberDeclaresDeathAfterThreeMisses(t *testing.T) {
	ping := &scriptedPinger{}
	var mu sync.Mutex
	var changes []bool
	p := newProber(ping, func(_ ProbeTarget, alive bool) {
		mu.Lock()
		changes = append(changes, alive)
		mu.Unlock()
	})
	target := ProbeTarget{Iface: "en5", Peer: peerLinkIP}
	p.SetTargets([]ProbeTarget{target})
	ctx := context.Background()
	miss := errors.New("timeout")
	steps := []struct {
		err   error
		alive bool
	}{
		{miss, false}, {nil, true}, {miss, true}, {miss, true}, {miss, false}, {miss, false}, {nil, true},
	}
	for i, s := range steps {
		ping.set(s.err)
		p.round(ctx)
		if got := p.Alive("en5", peerLinkIP); got != s.alive {
			t.Fatalf("step %d: alive = %v, want %v", i, got, s.alive)
		}
	}
	if !reflect.DeepEqual(changes, []bool{true, false, true}) {
		t.Fatalf("transitions = %v, want [true false true]", changes)
	}
	p.SetTargets(nil)
	if p.Alive("en5", peerLinkIP) {
		t.Fatal("a removed target is still alive")
	}
}

// scriptedPinger answers every echo with one settable result.
type scriptedPinger struct {
	mu  sync.Mutex
	err error
}

func (s *scriptedPinger) set(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *scriptedPinger) Ping(context.Context, netip.Addr, time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// fakeLinkDevice is a fakeDevice with the link verbs: it records every
// ConfigureLink and RemoveLink, and can refuse ConfigureLink.
type fakeLinkDevice struct {
	fakeDevice
	lmu       sync.Mutex
	links     []LinkConfig
	removed   []string
	refuseErr error
}

func (f *fakeLinkDevice) ConfigureLink(_ context.Context, cfg LinkConfig) (netip.Addr, error) {
	f.lmu.Lock()
	defer f.lmu.Unlock()
	if f.refuseErr != nil {
		return netip.Addr{}, f.refuseErr
	}
	f.links = append(f.links, cfg)
	return cfg.LinkIP, nil
}

func (f *fakeLinkDevice) RemoveLink(_ context.Context, iface string) error {
	f.lmu.Lock()
	defer f.lmu.Unlock()
	f.removed = append(f.removed, iface)
	return nil
}

func (f *fakeLinkDevice) lastLink() LinkConfig {
	f.lmu.Lock()
	defer f.lmu.Unlock()
	return f.links[len(f.links)-1]
}

// TestVanishedInterfaceIsRemovedAndReconfigured pins the link-event contract: an
// interface that vanishes is a RemoveLink, and its reappearance re-configures the
// same link — never a flag flip.
func TestVanishedInterfaceIsRemovedAndReconfigured(t *testing.T) {
	ctx := context.Background()
	dev := &fakeLinkDevice{}
	m, err := New(selfCIDR, withDevice(dev), withPinger(&scriptedPinger{}), WithLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	cfg := LinkConfig{Iface: "en5", PortOrdinal: 3, LinkIP: selfLinkIP}
	if _, err := m.ConfigureLink(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	m.HandleLinkEvent(ctx, linkwatch.Event{Iface: "en5", Gone: true})
	m.HandleLinkEvent(ctx, linkwatch.Event{Iface: "en5", Gone: true}) // both sources
	if !reflect.DeepEqual(dev.removed, []string{"en5"}) {
		t.Fatalf("removed = %v, want one RemoveLink for en5", dev.removed)
	}
	m.HandleLinkEvent(ctx, linkwatch.Event{Iface: "en5", Up: true})
	if len(dev.links) != 2 || dev.links[1] != cfg {
		t.Fatalf("links = %+v, want the same config re-applied on reappearance", dev.links)
	}
	m.HandleLinkEvent(ctx, linkwatch.Event{Iface: "en7", Gone: true})
	if len(dev.removed) != 1 {
		t.Fatalf("an unconfigured interface's vanishing drove RemoveLink: %v", dev.removed)
	}
}

// TestConfigureLinkUnsupportedDevice pins that a device without link verbs (the
// direct run-as-root device) reports ErrLinksUnsupported and plans no direct
// route.
func TestConfigureLinkUnsupportedDevice(t *testing.T) {
	ctx := context.Background()
	dev := &fakeDevice{}
	m, err := New(selfCIDR, withDevice(dev), withPinger(&scriptedPinger{}), WithLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ConfigureLink(ctx, LinkConfig{Iface: "en5"}); !errors.Is(err, ErrLinksUnsupported) {
		t.Fatalf("error = %v, want ErrLinksUnsupported", err)
	}
	m.SetDirectLinkStatus(upStatus())
	m.HandleLinkEvent(ctx, linkwatch.Event{Iface: "en5", Up: true})
	if err := m.Reconcile(ctx, []netv1.MeshPeerSpec{directPeerSpec()}); err != nil {
		t.Fatal(err)
	}
	if len(dev.last().Direct) != 0 {
		t.Fatalf("a device without link verbs got direct routes: %+v", dev.last().Direct)
	}
}
