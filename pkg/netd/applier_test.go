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
	"slices"
	"strings"
	"testing"

	"k3sm.io/darwin-net/pkg/mesh"
	"k3sm.io/darwin-net/pkg/podnet"
)

// TestDarwinApplierDerivesBothMeshAddresses pins that the helper path programs the
// same two-address datapath the direct path does. The mesh needs BOTH: the
// mesh-egress source on lo0 (bindable by the proxy and the control plane) and the
// utun's own point-to-point link address, without which macOS refuses every
// interface-bound route and no peer route can land. A daemon that derived only the
// first would bring a tunnel up that carries no routes — the defect this pins.
func TestDarwinApplierDerivesBothMeshAddresses(t *testing.T) {
	cidr := netip.MustParsePrefix("100.64.3.0/24")
	a := newDarwinApplier(cidr, quietLogger())

	wantEgress, err := podnet.MeshEgressIP(cidr)
	if err != nil {
		t.Fatalf("MeshEgressIP: %v", err)
	}
	wantLink, err := podnet.MeshLinkIP(cidr)
	if err != nil {
		t.Fatalf("MeshLinkIP: %v", err)
	}
	if a.meshIP != wantEgress {
		t.Errorf("meshIP = %s, want %s", a.meshIP, wantEgress)
	}
	if a.linkIP != wantLink {
		t.Errorf("linkIP = %s, want %s", a.linkIP, wantLink)
	}
	if a.meshIP == a.linkIP {
		t.Errorf("the daemon derived one address for both roles (%s): an address on the utun is reached over the utun, so the mesh IP would stop being loopback-dialable", a.meshIP)
	}
}

// TestDarwinApplierRefusesMeshWithoutBothAddresses pins the fail-fast: a node whose
// podCIDR cannot yield the pair never brings a route-less tunnel up. It performs no
// privileged operation, so it runs in the unit pass.
func TestDarwinApplierRefusesMeshWithoutBothAddresses(t *testing.T) {
	a := newDarwinApplier(netip.MustParsePrefix("100.64.0.0/16"), quietLogger())
	err := a.ConfigureMesh(context.Background(), "", mesh.DefaultListenPort, mesh.Plan{})
	if err == nil {
		t.Fatal("ConfigureMesh accepted a node podCIDR that yields no mesh addresses")
	}
	if !strings.Contains(err.Error(), "100.64.0.0/16") {
		t.Errorf("error %q does not name the offending podCIDR", err)
	}
}

// applierOps records the commands and route operations a darwinApplier drives,
// in order, and can be told to fail a route operation. It models the two pieces
// of kernel state they act on: lo0's aliases (-alias of an address that is not
// aliased fails, as ifconfig does) and the host routes, each either a live
// alias's route or a blackhole. Clear removes only a blackhole, as
// podnet.BlackholeRoutes does.
type applierOps struct {
	ops        []string
	clearErr   error
	installErr error
	lo0        map[netip.Addr]bool
	// routes maps a host route's destination to whether it is a blackhole.
	routes map[netip.Addr]bool
}

func newApplierOps() *applierOps {
	return &applierOps{lo0: make(map[netip.Addr]bool), routes: make(map[netip.Addr]bool)}
}

func (r *applierOps) command(_ context.Context, name string, args ...string) error {
	r.ops = append(r.ops, name+" "+strings.Join(args, " "))
	if name != "ifconfig" || len(args) != 3 {
		return nil
	}
	switch args[1] {
	case "alias":
		ip := netip.MustParseAddr(strings.TrimSuffix(args[2], "/32"))
		r.lo0[ip] = true
		r.routes[ip] = false
	case "-alias":
		ip := netip.MustParseAddr(args[2])
		if !r.lo0[ip] {
			return errors.New("ifconfig: ioctl (SIOCDIFADDR): Can't assign requested address")
		}
		delete(r.lo0, ip)
		delete(r.routes, ip)
	}
	return nil
}

func (r *applierOps) Install(_ context.Context, ip netip.Addr) error {
	r.ops = append(r.ops, "install-blackhole "+ip.String())
	if r.installErr != nil {
		return r.installErr
	}
	if bh, ok := r.routes[ip]; ok && !bh {
		return errors.New("another host route is held for the address")
	}
	r.routes[ip] = true
	return nil
}

func (r *applierOps) Clear(_ context.Context, ip netip.Addr) error {
	r.ops = append(r.ops, "clear-blackhole "+ip.String())
	if r.clearErr != nil {
		return r.clearErr
	}
	if r.routes[ip] {
		delete(r.routes, ip)
	}
	return nil
}

func (r *applierOps) List(_ context.Context, nodeCIDR netip.Prefix) ([]netip.Addr, error) {
	var out []netip.Addr
	for ip, bh := range r.routes {
		if bh && podnet.IsPodAddress(nodeCIDR, ip) {
			out = append(out, ip)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out, nil
}

// blackholed returns the destinations of the blackhole routes the fake holds,
// sorted.
func (r *applierOps) blackholed() []netip.Addr {
	var out []netip.Addr
	for ip, bh := range r.routes {
		if bh {
			out = append(out, ip)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// TestRemoveAliasInstallsBlackhole pins the helper path's pod-alias teardown: a
// pod address of the node /24 is blackholed right after its -alias, and the next
// EnsureAlias clears the blackhole before re-aliasing (failing if the clear
// fails); a Service VIP is never blackholed.
func TestRemoveAliasInstallsBlackhole(t *testing.T) {
	ctx := context.Background()
	newApplier := func() (*darwinApplier, *applierOps) {
		a := newDarwinApplier(netip.MustParsePrefix("100.64.3.0/24"), quietLogger())
		rec := newApplierOps()
		a.command = rec.command
		a.routes = rec
		return a, rec
	}
	pod := netip.MustParseAddr("100.64.3.17")
	vip := netip.MustParseAddr("10.43.0.80")

	t.Run("an aliased pod address is blackholed after its alias goes", func(t *testing.T) {
		a, rec := newApplier()
		if err := a.EnsureAlias(ctx, pod); err != nil {
			t.Fatalf("EnsureAlias: %v", err)
		}
		rec.ops = nil
		if err := a.RemoveAlias(ctx, pod); err != nil {
			t.Fatalf("RemoveAlias: %v", err)
		}
		want := []string{"ifconfig lo0 -alias 100.64.3.17", "install-blackhole 100.64.3.17"}
		if !slices.Equal(rec.ops, want) {
			t.Fatalf("RemoveAlias ops = %q, want %q", rec.ops, want)
		}
	})

	t.Run("an address netd never aliased is not blackholed", func(t *testing.T) {
		a, rec := newApplier()
		if err := a.RemoveAlias(ctx, pod); err != nil {
			t.Fatalf("RemoveAlias: %v", err)
		}
		if want := []string{"ifconfig lo0 -alias 100.64.3.17"}; !slices.Equal(rec.ops, want) {
			t.Fatalf("RemoveAlias ops = %q, want %q (an untracked, unplumbed address gets no blackhole)", rec.ops, want)
		}
		if got := rec.blackholed(); len(got) != 0 {
			t.Fatalf("blackholes = %v, want none", got)
		}
	})

	t.Run("an alias a previous daemon left on lo0 is blackholed", func(t *testing.T) {
		a, rec := newApplier()
		rec.lo0[pod], rec.routes[pod] = true, false
		if err := a.RemoveAlias(ctx, pod); err != nil {
			t.Fatalf("RemoveAlias: %v", err)
		}
		want := []string{"ifconfig lo0 -alias 100.64.3.17", "install-blackhole 100.64.3.17"}
		if !slices.Equal(rec.ops, want) {
			t.Fatalf("RemoveAlias ops = %q, want %q", rec.ops, want)
		}
	})

	t.Run("a tracked alias that will not go fails closed", func(t *testing.T) {
		a, rec := newApplier()
		if err := a.EnsureAlias(ctx, pod); err != nil {
			t.Fatalf("EnsureAlias: %v", err)
		}
		// The -alias fails but the alias's live host route is still there.
		delete(rec.lo0, pod)
		if err := a.RemoveAlias(ctx, pod); err == nil {
			t.Fatal("RemoveAlias succeeded over a live non-blackhole host route")
		}
	})

	t.Run("ensure clears the blackhole before aliasing", func(t *testing.T) {
		a, rec := newApplier()
		if err := a.EnsureAlias(ctx, pod); err != nil {
			t.Fatalf("EnsureAlias: %v", err)
		}
		want := []string{"clear-blackhole 100.64.3.17", "ifconfig lo0 alias 100.64.3.17/32"}
		if !slices.Equal(rec.ops, want) {
			t.Fatalf("EnsureAlias ops = %q, want %q", rec.ops, want)
		}
	})

	t.Run("a failed clear fails ensure and plumbs nothing", func(t *testing.T) {
		a, rec := newApplier()
		rec.clearErr = errors.New("routing socket refused")
		if err := a.EnsureAlias(ctx, pod); err == nil {
			t.Fatal("EnsureAlias succeeded although the stale blackhole could not be cleared")
		}
		if want := []string{"clear-blackhole 100.64.3.17"}; !slices.Equal(rec.ops, want) {
			t.Fatalf("EnsureAlias ops = %q, want %q", rec.ops, want)
		}
	})

	t.Run("a failed install is returned and the retry converges", func(t *testing.T) {
		a, rec := newApplier()
		if err := a.EnsureAlias(ctx, pod); err != nil {
			t.Fatalf("EnsureAlias: %v", err)
		}
		rec.installErr = errors.New("routing socket refused")
		if err := a.RemoveAlias(ctx, pod); err == nil {
			t.Fatal("RemoveAlias hid a failed blackhole install")
		}
		rec.installErr, rec.ops = nil, nil
		if err := a.RemoveAlias(ctx, pod); err != nil {
			t.Fatalf("retried RemoveAlias: %v", err)
		}
		if want := []string{"install-blackhole 100.64.3.17"}; !slices.Equal(rec.ops, want) {
			t.Fatalf("retried RemoveAlias ops = %q, want %q (the alias is gone; only the blackhole is owed)", rec.ops, want)
		}
	})

	t.Run("a Service VIP is never blackholed", func(t *testing.T) {
		a, rec := newApplier()
		if err := a.EnsureAlias(ctx, vip); err != nil {
			t.Fatalf("EnsureAlias: %v", err)
		}
		if err := a.RemoveAlias(ctx, vip); err != nil {
			t.Fatalf("RemoveAlias: %v", err)
		}
		want := []string{"ifconfig lo0 alias 10.43.0.80/32", "ifconfig lo0 -alias 10.43.0.80"}
		if !slices.Equal(rec.ops, want) {
			t.Fatalf("VIP ops = %q, want %q", rec.ops, want)
		}
	})

	t.Run("the scope follows an adopted node podCIDR", func(t *testing.T) {
		a, rec := newApplier()
		rec.lo0[pod], rec.routes[pod] = true, false
		if err := a.SetNodePodCIDR(ctx, netip.MustParsePrefix("100.64.9.0/24")); err != nil {
			t.Fatalf("SetNodePodCIDR: %v", err)
		}
		rec.ops = nil
		if err := a.RemoveAlias(ctx, pod); err != nil {
			t.Fatalf("RemoveAlias: %v", err)
		}
		if want := []string{"ifconfig lo0 -alias 100.64.3.17"}; !slices.Equal(rec.ops, want) {
			t.Fatalf("ops after adopting another /24 = %q, want %q (no longer this node's pod)", rec.ops, want)
		}
	})
}

// TestBlackholeSweeps pins the two sweeps: a node podCIDR change clears the old
// /24's blackholes and nothing else, and the start-up sweep clears a stale
// blackhole in the current /24 while leaving a live alias's route alone.
func TestBlackholeSweeps(t *testing.T) {
	ctx := context.Background()
	addr := netip.MustParseAddr
	oldCIDR := netip.MustParsePrefix("100.64.3.0/24")
	newCIDR := netip.MustParsePrefix("100.64.9.0/24")

	cases := []struct {
		name string
		// blackholes and aliases seed the fake's host routes.
		blackholes, aliases []string
		run                 func(*darwinApplier) error
		wantBlackholes      []netip.Addr
		wantAliasRoutes     []netip.Addr
	}{
		{
			name:       "a CIDR change sweeps the old /24's blackholes only",
			blackholes: []string{"100.64.3.17", "100.64.3.200", "100.64.4.9", "100.64.9.5"},
			aliases:    []string{"10.43.0.80"},
			run:        func(a *darwinApplier) error { return a.SetNodePodCIDR(ctx, newCIDR) },
			// Another node's /24 and the new /24 are untouched; so is a VIP alias.
			wantBlackholes:  []netip.Addr{addr("100.64.4.9"), addr("100.64.9.5")},
			wantAliasRoutes: []netip.Addr{addr("10.43.0.80")},
		},
		{
			name:            "an unchanged CIDR sweeps nothing",
			blackholes:      []string{"100.64.3.17"},
			run:             func(a *darwinApplier) error { return a.SetNodePodCIDR(ctx, oldCIDR) },
			wantBlackholes:  []netip.Addr{addr("100.64.3.17")},
			wantAliasRoutes: nil,
		},
		{
			name:       "the start-up sweep clears a stale blackhole and spares a live alias",
			blackholes: []string{"100.64.3.17", "100.64.4.9"},
			aliases:    []string{"100.64.3.18"},
			run: func(a *darwinApplier) error {
				a.sweepStaleBlackholes(ctx)
				return nil
			},
			wantBlackholes:  []netip.Addr{addr("100.64.4.9")},
			wantAliasRoutes: []netip.Addr{addr("100.64.3.18")},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newDarwinApplier(oldCIDR, quietLogger())
			rec := newApplierOps()
			a.command, a.routes = rec.command, rec
			for _, s := range c.blackholes {
				rec.routes[addr(s)] = true
			}
			for _, s := range c.aliases {
				rec.lo0[addr(s)], rec.routes[addr(s)] = true, false
			}
			if err := c.run(a); err != nil {
				t.Fatalf("run: %v", err)
			}
			if got := rec.blackholed(); !slices.Equal(got, c.wantBlackholes) {
				t.Errorf("blackholes = %v, want %v", got, c.wantBlackholes)
			}
			var aliasRoutes []netip.Addr
			for ip, bh := range rec.routes {
				if !bh {
					aliasRoutes = append(aliasRoutes, ip)
				}
			}
			slices.SortFunc(aliasRoutes, netip.Addr.Compare)
			if !slices.Equal(aliasRoutes, c.wantAliasRoutes) {
				t.Errorf("alias routes = %v, want %v", aliasRoutes, c.wantAliasRoutes)
			}
		})
	}
}

// quietLogger is a logger the applier tests can pass without emitting output. The
// package's other tests live in netd_test and cannot share it.
func quietLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }
