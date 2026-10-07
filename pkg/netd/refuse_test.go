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
	"log/slog"
	"net/netip"
	"testing"

	"k3sm.io/darwin-net/pkg/mesh"
)

// TestAllocatedPodsForTheRefusal pins the allocation the mesh device consults
// before it answers a peer's SYN with a RST (mesh.DeviceConfig.Allocated). The
// direction that matters is never to call a live pod unallocated, so: an unknown
// allocation (no read of lo0 yet, a failed read, a re-pointed /24) answers
// "allocated" for every address; the lo0 read is taken before the device comes up;
// an address is allocated from the moment EnsureAlias starts and unallocated only
// once its lo0 alias is known gone.
func TestAllocatedPodsForTheRefusal(t *testing.T) {
	ctx := context.Background()
	ip := netip.MustParseAddr
	live, free := ip("100.64.3.17"), ip("100.64.3.99")
	type world struct {
		h   *utunHost
		a   *darwinApplier
		cfg *mesh.DeviceConfig
	}
	setup := func(t *testing.T) world {
		t.Helper()
		h := newUTUNHost()
		a := utunApplier(h)
		w := world{h: h, a: a, cfg: &mesh.DeviceConfig{}}
		a.newDevice = func(cfg mesh.DeviceConfig, _ *slog.Logger) meshDevice {
			*w.cfg = cfg
			return &fakeDevice{h: h, link: cfg.LinkIP, onUp: func() {
				// At bring-up the allocation must already be known.
				if cfg.Allocated == nil || cfg.Allocated(live) != h.lo0[live] || cfg.Allocated(free) {
					t.Errorf("at device Up: allocated(%s)/allocated(%s) not yet read from lo0", live, free)
				}
			}}
		}
		return w
	}
	configure := func(t *testing.T, a *darwinApplier) {
		t.Helper()
		if err := a.ConfigureMesh(ctx, "key", mesh.DefaultListenPort, mesh.Plan{}); err != nil {
			t.Fatalf("ConfigureMesh: %v", err)
		}
	}

	t.Run("unknown before any read answers allocated", func(t *testing.T) {
		w := setup(t)
		if !w.a.pods.allocated(free) {
			t.Fatal("a fresh executor called an address unallocated before reading lo0")
		}
	})

	t.Run("the lo0 read seeds the allocation before the device comes up", func(t *testing.T) {
		w := setup(t)
		w.h.lo0[live] = true
		configure(t, w.a)
		if w.cfg.NodePodCIDR != netip.MustParsePrefix("100.64.3.0/24") {
			t.Fatalf("device NodePodCIDR = %s, want the node /24", w.cfg.NodePodCIDR)
		}
		if !w.cfg.Allocated(live) || w.cfg.Allocated(free) {
			t.Fatalf("allocated(%s)=%v allocated(%s)=%v, want true/false", live, w.cfg.Allocated(live), free, w.cfg.Allocated(free))
		}
	})

	t.Run("ensure allocates and remove frees", func(t *testing.T) {
		w := setup(t)
		w.h.lo0[live] = true
		configure(t, w.a)
		if err := w.a.EnsureAlias(ctx, free); err != nil {
			t.Fatalf("EnsureAlias: %v", err)
		}
		if !w.a.pods.allocated(free) {
			t.Fatal("an aliased address is unallocated")
		}
		if err := w.a.RemoveAlias(ctx, free); err != nil {
			t.Fatalf("RemoveAlias: %v", err)
		}
		if w.a.pods.allocated(free) {
			t.Fatal("a removed address is still allocated")
		}
		if !w.a.pods.allocated(live) {
			t.Fatal("removing one address freed another")
		}
	})

	t.Run("an alias that would not go stays allocated", func(t *testing.T) {
		w := setup(t)
		configure(t, w.a)
		if err := w.a.EnsureAlias(ctx, free); err != nil {
			t.Fatalf("EnsureAlias: %v", err)
		}
		delete(w.h.lo0, free) // the -alias now fails
		_ = w.a.RemoveAlias(ctx, free)
		if !w.a.pods.allocated(free) {
			t.Fatal("an address whose lo0 -alias failed was freed")
		}
	})

	t.Run("a failed lo0 read forgets the allocation", func(t *testing.T) {
		w := setup(t)
		configure(t, w.a)
		w.a.ifaceAddrs = func() (map[string][]netip.Addr, error) { return nil, errors.New("sysctl failed") }
		_ = w.a.ConfigureMesh(ctx, "key", mesh.DefaultListenPort, mesh.Plan{})
		if !w.a.pods.allocated(free) {
			t.Fatal("an unreadable lo0 left an address unallocated")
		}
	})

	t.Run("a re-pointed /24 forgets the allocation", func(t *testing.T) {
		w := setup(t)
		configure(t, w.a)
		if err := w.a.RemoveMesh(ctx); err != nil {
			t.Fatalf("RemoveMesh: %v", err)
		}
		if err := w.a.SetNodePodCIDR(ctx, netip.MustParsePrefix("100.64.9.0/24")); err != nil {
			t.Fatalf("SetNodePodCIDR: %v", err)
		}
		if !w.a.pods.allocated(ip("100.64.9.50")) {
			t.Fatal("the new /24's addresses are unallocated before any read")
		}
	})
}
