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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/mesh"
	"k3sm.io/darwin-net/pkg/netd/wire"
)

// linkPriv is a rootless Privileged that records the plans and the link
// operations the server let through.
type linkPriv struct {
	mu      sync.Mutex
	plans   []mesh.Plan
	links   []LinkSpec
	removed []string
	linkErr error
}

func (p *linkPriv) EnsureAlias(context.Context, netip.Addr) error { return nil }
func (p *linkPriv) RemoveAlias(context.Context, netip.Addr) error { return nil }
func (p *linkPriv) RemoveMesh(context.Context) error              { return nil }
func (p *linkPriv) SetNodePodCIDR(context.Context, netip.Prefix) error {
	return nil
}

func (p *linkPriv) BindPort(context.Context, string, netip.AddrPort) (*os.File, error) {
	return nil, errors.New("not used")
}

func (p *linkPriv) ConfigureMesh(_ context.Context, _ string, _ int, plan mesh.Plan) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.plans = append(p.plans, plan)
	return nil
}

func (p *linkPriv) ConfigureLink(_ context.Context, spec LinkSpec) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.linkErr != nil {
		return p.linkErr
	}
	p.links = append(p.links, spec)
	return nil
}

func (p *linkPriv) RemoveLink(_ context.Context, iface string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removed = append(p.removed, iface)
	return nil
}

func (p *linkPriv) planCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.plans)
}

type keyResolver struct{}

func (keyResolver) Resolve(context.Context, string) (string, error) { return "key", nil }

// The fixture node: index 0 (100.64.0.0/24) on a six-port Mac; en5 is
// Thunderbolt 4 (ordinal 3), en6 Thunderbolt 5 (ordinal 4).
var (
	linkSelf = netip.MustParsePrefix("100.64.0.0/24")
	linkHW   = map[string]int{"en2": 1, "en3": 2, "en4": 3, "en5": 4, "en6": 5, "en7": 6}
)

func linkIP(t *testing.T, idx, port int) netip.Addr {
	t.Helper()
	a, err := netv1alpha1.LinkIP(idx, port)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func linkServer(t *testing.T, priv Privileged) *Server {
	t.Helper()
	return NewServer(Config{
		NodePodCIDR:     linkSelf,
		Privileged:      priv,
		MeshKeyResolver: keyResolver{},
		HardwarePorts:   func(context.Context) (map[string]int, error) { return linkHW, nil },
		Logger:          slog.New(slog.DiscardHandler),
	})
}

// call dispatches one request through the server's own decode-and-route path.
func call(t *testing.T, s *Server, req wire.Request) wire.Response {
	t.Helper()
	req.Version = wire.CurrentVersion()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := s.dispatch(context.Background(), newConnState(wire.DefaultMaxPerConn), b)
	return resp
}

func pubKey(t *testing.T) string {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k)
}

// meshReq is a ConfigureMesh for this node with the given peer /24s.
func meshReq(t *testing.T, direct []wire.DirectRouteArg, peers ...string) wire.Request {
	t.Helper()
	args := &wire.ConfigureMeshArgs{LocalPrivKeyRef: "ref", NodePodCIDR: linkSelf.String(), DirectRoutes: direct}
	for i, p := range peers {
		args.Peers = append(args.Peers, wire.MeshPeerArg{PubKey: pubKey(t), Endpoint: fmt.Sprintf("192.0.2.%d:51820", 10+i), AllowedIPs: []string{p}})
	}
	return wire.Request{Verb: wire.VerbConfigureMesh, ConfigureMesh: args}
}

func linkReq(iface string, ordinal int, peer netip.Addr) wire.Request {
	args := &wire.ConfigureLinkArgs{Iface: iface, PortOrdinal: ordinal}
	if peer.IsValid() {
		args.PeerLinkIP = peer.String()
	}
	return wire.Request{Verb: wire.VerbConfigureLink, ConfigureLink: args}
}

// TestGatewayDerivedFromPeerPodCIDR pins the root-side next-hop rule: a direct
// route's gateway must be LinkIP(idxOf(peer /24), p) for some port p. A client
// that names another node's link address (even one on a link the daemon did
// configure), a LAN address, a self-assigned link-local address, or this node's
// own link address is refused, and the refusal installs nothing.
func TestGatewayDerivedFromPeerPodCIDR(t *testing.T) {
	priv := &linkPriv{}
	s := linkServer(t, priv)
	peer1, peer2 := "100.64.1.0/24", "100.64.2.0/24"
	if r := call(t, s, meshReq(t, nil, peer1, peer2)); !r.OK {
		t.Fatalf("ConfigureMesh: %s", r.Error)
	}
	// en5 is cabled to node 1's port 0; en6 to node 2's port 2.
	gw1, gw2 := linkIP(t, 1, 0), linkIP(t, 2, 2)
	for _, l := range []wire.Request{linkReq("en5", 3, gw1), linkReq("en6", 4, gw2)} {
		if r := call(t, s, l); !r.OK {
			t.Fatalf("ConfigureLink: %s", r.Error)
		}
	}

	cases := []struct {
		name    string
		route   wire.DirectRouteArg
		wantErr string
	}{
		{"another node's link address on a configured link", wire.DirectRouteArg{PeerPodCIDR: peer1, Gateway: gw2.String(), Iface: "en6"}, "not a direct-link address of the node owning"},
		{"a LAN address", wire.DirectRouteArg{PeerPodCIDR: peer1, Gateway: "192.168.1.20", Iface: "en5"}, "not a direct-link address of the node owning"},
		{"a self-assigned link-local address", wire.DirectRouteArg{PeerPodCIDR: peer1, Gateway: "169.254.7.7", Iface: "en5"}, "not a direct-link address of the node owning"},
		{"this node's own link address", wire.DirectRouteArg{PeerPodCIDR: peer1, Gateway: linkIP(t, 0, 3).String(), Iface: "en5"}, "not a direct-link address of the node owning"},
		{"the right node, a link toward someone else", wire.DirectRouteArg{PeerPodCIDR: peer1, Gateway: linkIP(t, 1, 5).String(), Iface: "en5"}, "configured toward"},
		{"a link the daemon never configured", wire.DirectRouteArg{PeerPodCIDR: peer1, Gateway: gw1.String(), Iface: "en7"}, "not a configured direct link"},
		{"this node's own /24", wire.DirectRouteArg{PeerPodCIDR: linkSelf.String(), Gateway: linkIP(t, 0, 0).String(), Iface: "en5"}, "this node's own /24"},
		{"a /24 outside the cluster", wire.DirectRouteArg{PeerPodCIDR: "10.1.0.0/24", Gateway: gw1.String(), Iface: "en5"}, "not a node /24 of the cluster"},
		{"a /24 that is no peer of the request", wire.DirectRouteArg{PeerPodCIDR: "100.64.3.0/24", Gateway: linkIP(t, 3, 0).String(), Iface: "en5"}, "not a mesh peer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := priv.planCount()
			r := call(t, s, meshReq(t, []wire.DirectRouteArg{tc.route}, peer1, peer2))
			if r.OK {
				t.Fatal("the daemon accepted the direct route")
			}
			if !strings.Contains(r.Error, tc.wantErr) {
				t.Errorf("error %q does not say %q", r.Error, tc.wantErr)
			}
			if priv.planCount() != before {
				t.Error("a refused request still applied a plan (all-or-nothing)")
			}
		})
	}

	// The derived gateways are admitted, both at once, as /25 pairs over their
	// cables, with every peer's utun /24 kept.
	r := call(t, s, meshReq(t, []wire.DirectRouteArg{
		{PeerPodCIDR: peer1, Gateway: gw1.String(), Iface: "en5"},
		{PeerPodCIDR: peer2, Gateway: gw2.String(), Iface: "en6"},
	}, peer1, peer2))
	if !r.OK {
		t.Fatalf("well-formed direct routes refused: %s", r.Error)
	}
	plan := priv.plans[len(priv.plans)-1]
	var utun, direct int
	for _, rt := range plan.Routes {
		if rt.Direct() {
			direct++
		} else {
			utun++
		}
	}
	if utun != 2 || direct != 4 {
		t.Fatalf("plan routes = %v, want 2 utun /24s and 4 direct /25s", plan.Routes)
	}

	// All-or-nothing: one bad route among good ones refuses the lot.
	before := priv.planCount()
	r = call(t, s, meshReq(t, []wire.DirectRouteArg{
		{PeerPodCIDR: peer1, Gateway: gw1.String(), Iface: "en5"},
		{PeerPodCIDR: peer2, Gateway: "192.168.1.20", Iface: "en6"},
	}, peer1, peer2))
	if r.OK || priv.planCount() != before {
		t.Fatalf("a request with one bad direct route was applied (ok=%v)", r.OK)
	}
}

// TestConfigureLinkValidatesRootSide pins the ConfigureLink policy: the identity
// must be confirmed by a ConfigureMesh first; the interface must be a Thunderbolt
// hardware port by the system's mapping (never by name) and the ordinal its
// receptacle − 1; the address is derived here and a disagreeing client value is
// refused; the peer address must be another reserved-half address; at most eight
// links; and a confirmed identity cannot move while a link is live.
func TestConfigureLinkValidatesRootSide(t *testing.T) {
	priv := &linkPriv{}
	s := linkServer(t, priv)
	peer := linkIP(t, 1, 0)

	if r := call(t, s, linkReq("en5", 3, peer)); r.OK || !strings.Contains(r.Error, "not confirmed") {
		t.Fatalf("ConfigureLink before any ConfigureMesh: ok=%v err=%q, want a refusal naming the unconfirmed identity", r.OK, r.Error)
	}
	if r := call(t, s, meshReq(t, nil)); !r.OK {
		t.Fatalf("ConfigureMesh: %s", r.Error)
	}
	refused := []struct {
		name string
		req  wire.Request
		want string
	}{
		{"not a Thunderbolt port", linkReq("en0", 0, peer), "not a Thunderbolt hardware port"},
		{"not an Ethernet-class name", linkReq("bridge0", 0, peer), "not an Ethernet-class interface"},
		{"wrong ordinal", linkReq("en5", 2, peer), "port ordinal 3"},
		{"a peer outside the reserved halves", linkReq("en5", 3, netip.MustParseAddr("169.254.9.9")), "not another node's direct-link address"},
		{"this port's own address as the peer", linkReq("en5", 3, linkIP(t, 0, 3)), "not another node's direct-link address"},
		{"a disagreeing linkIP", wire.Request{Verb: wire.VerbConfigureLink, ConfigureLink: &wire.ConfigureLinkArgs{Iface: "en5", PortOrdinal: 3, LinkIP: linkIP(t, 0, 2).String()}}, "disagrees with the derived"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			if r := call(t, s, tc.req); r.OK || !strings.Contains(r.Error, tc.want) {
				t.Fatalf("ok=%v err=%q, want a refusal containing %q", r.OK, r.Error, tc.want)
			}
		})
	}
	if len(priv.links) != 0 {
		t.Fatalf("refused requests reached the executor: %+v", priv.links)
	}

	r := call(t, s, wire.Request{Verb: wire.VerbConfigureLink, ConfigureLink: &wire.ConfigureLinkArgs{Iface: "en5", PortOrdinal: 3, LinkIP: linkIP(t, 0, 3).String(), PeerLinkIP: peer.String()}})
	if !r.OK || r.LinkIP != linkIP(t, 0, 3).String() {
		t.Fatalf("ConfigureLink: ok=%v err=%q linkIP=%q, want the derived %s", r.OK, r.Error, r.LinkIP, linkIP(t, 0, 3))
	}
	if got := priv.links[0]; got != (LinkSpec{Iface: "en5", LinkIP: linkIP(t, 0, 3), PeerLinkIP: peer}) {
		t.Fatalf("executor got %+v", got)
	}

	// The identity cannot move under a live link.
	moved := meshReq(t, nil)
	moved.ConfigureMesh.NodePodCIDR = "100.64.9.0/24"
	if r := call(t, s, moved); r.OK || !strings.Contains(r.Error, "direct link") {
		t.Fatalf("identity moved under a live link: ok=%v err=%q", r.OK, r.Error)
	}

	// At most eight links.
	many := map[string]int{}
	for i := 0; i < 9; i++ {
		many[fmt.Sprintf("en%d", 20+i)] = i%8 + 1
	}
	s.cfg.HardwarePorts = func(context.Context) (map[string]int, error) { return many, nil }
	ok := 1 // en5 is already configured
	for i := 0; i < 9; i++ {
		if r := call(t, s, linkReq(fmt.Sprintf("en%d", 20+i), i%8, netip.Addr{})); r.OK {
			ok++
		} else if !strings.Contains(r.Error, "limit") {
			t.Fatalf("unexpected refusal: %s", r.Error)
		}
	}
	if ok != MaxLinks {
		t.Fatalf("%d links configured, want the limit %d", ok, MaxLinks)
	}

	// RemoveLink forgets the link and releases the identity once nothing is live.
	if r := call(t, s, wire.Request{Verb: wire.VerbRemoveLink, RemoveLink: &wire.RemoveLinkArgs{Iface: "en5"}}); !r.OK {
		t.Fatalf("RemoveLink: %s", r.Error)
	}
	if !slices.Contains(priv.removed, "en5") {
		t.Fatalf("RemoveLink did not reach the executor: %v", priv.removed)
	}
	if r := call(t, s, wire.Request{Verb: wire.VerbRemoveLink, RemoveLink: &wire.RemoveLinkArgs{Iface: "en0"}}); r.OK {
		t.Fatal("RemoveLink of an interface that is neither a link nor a Thunderbolt port was accepted")
	}
}

// TestReplyCarriesTheDaemonVersion pins that every reply, success or refusal,
// carries the daemon's own version: it is what the client gates DirectRoutes on.
func TestReplyCarriesTheDaemonVersion(t *testing.T) {
	s := linkServer(t, &linkPriv{})
	for _, req := range []wire.Request{linkReq("en0", 0, netip.Addr{}), {Verb: "NoSuchVerb"}, meshReq(t, nil)} {
		if r := call(t, s, req); r.Version != wire.CurrentVersion() {
			t.Fatalf("%s reply version = %+v, want %+v", req.Verb, r.Version, wire.CurrentVersion())
		}
	}
}
