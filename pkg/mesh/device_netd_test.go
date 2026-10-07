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
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/linkwatch"
	"k3sm.io/darwin-net/pkg/netd/wire"
)

// scriptedHelper is a netd helper as the client sees it: it reports a fixed
// protocol version on every reply and, at minor 0, answers ConfigureLink the way
// a 1.0 daemon does (unknown verb). It records every ConfigureMesh's DirectRoutes.
type scriptedHelper struct {
	version wire.Version
	mu      sync.Mutex
	replied bool
	meshes  [][]wire.DirectRouteArg
	links   []wire.ConfigureLinkArgs
	linkErr error
}

func (h *scriptedHelper) reply() {
	h.mu.Lock()
	h.replied = true
	h.mu.Unlock()
}

func (h *scriptedHelper) ConfigureMesh(_ context.Context, _ string, _ int, _ netip.Prefix, _ []wire.MeshPeerArg, direct []wire.DirectRouteArg) error {
	h.reply()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.meshes = append(h.meshes, direct)
	return nil
}

func (h *scriptedHelper) RemoveMesh(context.Context) error { h.reply(); return nil }

func (h *scriptedHelper) ConfigureLink(_ context.Context, args wire.ConfigureLinkArgs) (netip.Addr, error) {
	h.reply()
	if !h.version.SupportsDirectLinks() {
		return netip.Addr{}, errors.New(`netd ConfigureLink rejected: unknown verb "ConfigureLink"`)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.linkErr != nil {
		return netip.Addr{}, h.linkErr
	}
	h.links = append(h.links, args)
	return netip.ParseAddr(args.LinkIP)
}

func (h *scriptedHelper) RemoveLink(context.Context, string) error { h.reply(); return nil }

func (h *scriptedHelper) HelperVersion() (wire.Version, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.version, h.replied
}

func (h *scriptedHelper) sentDirect() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, d := range h.meshes {
		n += len(d)
	}
	return n
}

// helperMesh builds a Mesh over a helper-backed device talking to h, with the
// cable to nodeB up in status, locally, and in the probe.
func helperMesh(t *testing.T, h *scriptedHelper, log *slog.Logger) *Mesh {
	t.Helper()
	ctx := context.Background()
	dev := newNetdDeviceWith(h, "ref", DefaultListenPort, selfCIDR, log)
	m, err := New(selfCIDR, withDevice(dev), withPinger(&scriptedPinger{}), WithLogger(log))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	m.SetDirectLinkStatus(upStatus())
	m.HandleLinkEvent(ctx, linkwatch.Event{Iface: "en5", Up: true})
	return m
}

// TestClientNeverSendsDirectRoutesToOldHelper pins the version gate: a helper that
// reports protocol 1.0 — which would decode DirectRoutes and silently drop them —
// is never sent any, whatever the plan wants. ConfigureLink against it yields
// ErrLinksUnsupported and exactly one Info line, and the mesh keeps running over
// the tunnel. A 1.1 helper gets DirectRoutes only for a link it accepted, toward
// the gateway it accepted it for.
func TestClientNeverSendsDirectRoutesToOldHelper(t *testing.T) {
	ctx := context.Background()
	peers := []netv1.MeshPeerSpec{directPeerSpec()}
	link := LinkConfig{Iface: "en5", PortOrdinal: 3, LinkIP: selfLinkIP}

	t.Run("a 1.0 helper", func(t *testing.T) {
		var logs bytes.Buffer
		log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
		h := &scriptedHelper{version: wire.Version{Major: 1, Minor: 0}}
		m := helperMesh(t, h, log)
		for range 3 {
			if _, err := m.ConfigureLink(ctx, link); !errors.Is(err, ErrLinksUnsupported) {
				t.Fatalf("ConfigureLink error = %v, want ErrLinksUnsupported", err)
			}
		}
		m.prober.round(ctx)
		if err := m.Reconcile(ctx, peers); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		// Even a plan carrying a direct peer (built by hand, as a buggy caller
		// might) must not get through the device to an old helper.
		plan, err := BuildPlan(selfCIDR, peers, DirectRoutes{"nodeB": {Iface: "en5", Gateway: peerLinkIP}})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.dev.Apply(ctx, plan); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if n := h.sentDirect(); n != 0 {
			t.Fatalf("sent %d direct routes to a 1.0 helper", n)
		}
		if len(h.meshes) < 3 {
			t.Fatalf("the mesh stopped programming the helper (%d ConfigureMesh calls); it must run tunnel-only", len(h.meshes))
		}
		if got := strings.Count(logs.String(), "predates direct links"); got != 1 {
			t.Fatalf("the old-helper line was logged %d times, want once:\n%s", got, logs.String())
		}
	})

	t.Run("a helper replaced by a 1.0 one after accepting a link", func(t *testing.T) {
		h := &scriptedHelper{version: wire.Version{Major: 1, Minor: 1}}
		m := helperMesh(t, h, discardLogger())
		if _, err := m.ConfigureLink(ctx, LinkConfig{Iface: "en5", PortOrdinal: 3, LinkIP: selfLinkIP, PeerLinkIP: peerLinkIP}); err != nil {
			t.Fatalf("ConfigureLink: %v", err)
		}
		h.mu.Lock()
		h.version = wire.Version{Major: 1, Minor: 0} // a downgrade restarted the helper
		h.mu.Unlock()
		plan, err := BuildPlan(selfCIDR, peers, DirectRoutes{"nodeB": {Iface: "en5", Gateway: peerLinkIP}})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.dev.Apply(ctx, plan); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if n := h.sentDirect(); n != 0 {
			t.Fatalf("sent %d direct routes to a helper whose last reply said 1.0", n)
		}
	})

	t.Run("a 1.1 helper before any ConfigureLink", func(t *testing.T) {
		h := &scriptedHelper{version: wire.Version{Major: 1, Minor: 1}}
		m := helperMesh(t, h, discardLogger())
		plan, err := BuildPlan(selfCIDR, peers, DirectRoutes{"nodeB": {Iface: "en5", Gateway: peerLinkIP}})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.dev.Apply(ctx, plan); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if n := h.sentDirect(); n != 0 {
			t.Fatalf("sent %d direct routes for a link the helper never accepted", n)
		}
	})

	t.Run("a 1.1 helper after ConfigureLink", func(t *testing.T) {
		h := &scriptedHelper{version: wire.Version{Major: 1, Minor: 1}}
		m := helperMesh(t, h, discardLogger())
		if _, err := m.ConfigureLink(ctx, link); err != nil {
			t.Fatalf("ConfigureLink: %v", err)
		}
		m.prober.round(ctx)
		if err := m.Reconcile(ctx, peers); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		h.mu.Lock()
		last := h.meshes[len(h.meshes)-1]
		lastLink := h.links[len(h.links)-1]
		h.mu.Unlock()
		want := wire.DirectRouteArg{PeerPodCIDR: peerCIDR.String(), Gateway: peerLinkIP.String(), Iface: "en5"}
		if len(last) != 1 || last[0] != want {
			t.Fatalf("DirectRoutes = %+v, want [%+v]", last, want)
		}
		if lastLink.PeerLinkIP != peerLinkIP.String() {
			t.Fatalf("the link was re-confirmed toward %q before the routes were sent, want %s", lastLink.PeerLinkIP, peerLinkIP)
		}

		// The helper refuses the link (a restart lost it, configd re-added the
		// member and the removal failed, ...): the next plan sends no DirectRoutes.
		h.mu.Lock()
		h.linkErr = errors.New("netd ConfigureLink rejected: en5 is still a member of bridge0")
		h.mu.Unlock()
		if err := m.Reconcile(ctx, peers); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		h.mu.Lock()
		last = h.meshes[len(h.meshes)-1]
		h.mu.Unlock()
		if len(last) != 0 {
			t.Fatalf("DirectRoutes sent after the helper refused the link: %+v", last)
		}
	})
}
