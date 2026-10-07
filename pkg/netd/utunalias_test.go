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
	"strings"
	"testing"

	"k3sm.io/darwin-net/pkg/mesh"
)

// utunHost models the kernel state the alias path touches: lo0's and the mesh
// utun's IPv4 addresses and the host routes. It records every operation in
// order; a route operation is recorded with a "route " prefix so a test can
// count them. utunAddErr fails the utun alias add.
type utunHost struct {
	ops        []string
	lo0        map[netip.Addr]bool
	utun       map[netip.Addr]bool
	utunUp     bool
	blackholes map[netip.Addr]bool
	utunAddErr error
}

const fakeUTUN = "utun7"

func newUTUNHost() *utunHost {
	return &utunHost{lo0: map[netip.Addr]bool{}, utun: map[netip.Addr]bool{}, blackholes: map[netip.Addr]bool{}}
}

func (h *utunHost) command(_ context.Context, name string, args ...string) error {
	h.ops = append(h.ops, name+" "+strings.Join(args, " "))
	if name != "ifconfig" || len(args) < 3 {
		return fmt.Errorf("unexpected command %s %v", name, args)
	}
	switch {
	case args[0] == "lo0" && args[1] == "alias":
		h.lo0[netip.MustParseAddr(strings.TrimSuffix(args[2], "/32"))] = true
	case args[0] == "lo0" && args[1] == "-alias":
		ip := netip.MustParseAddr(args[2])
		if !h.lo0[ip] {
			return errors.New("ifconfig: ioctl (SIOCDIFADDR): Can't assign requested address")
		}
		delete(h.lo0, ip)
	case args[0] == fakeUTUN && args[1] == "inet" && len(args) == 7 && args[6] == "alias":
		if !h.utunUp {
			return errors.New("interface utun7 does not exist")
		}
		if h.utunAddErr != nil {
			return h.utunAddErr
		}
		h.utun[netip.MustParseAddr(args[2])] = true
	case args[0] == fakeUTUN && args[1] == "inet" && len(args) == 4 && args[3] == "-alias":
		ip := netip.MustParseAddr(args[2])
		if !h.utun[ip] {
			return errors.New("ifconfig: ioctl (SIOCDIFADDR): Can't assign requested address")
		}
		delete(h.utun, ip)
	default:
		return fmt.Errorf("unexpected ifconfig %v", args)
	}
	return nil
}

func (h *utunHost) Install(_ context.Context, ip netip.Addr) error {
	h.ops = append(h.ops, "route install-blackhole "+ip.String())
	h.blackholes[ip] = true
	return nil
}

func (h *utunHost) Clear(_ context.Context, ip netip.Addr) error {
	h.ops = append(h.ops, "route clear-blackhole "+ip.String())
	delete(h.blackholes, ip)
	return nil
}

func (h *utunHost) List(context.Context, netip.Prefix) ([]netip.Addr, error) { return nil, nil }

func (h *utunHost) ifaceAddrs() (map[string][]netip.Addr, error) {
	out := map[string][]netip.Addr{}
	for ip := range h.lo0 {
		out["lo0"] = append(out["lo0"], ip)
	}
	if h.utunUp {
		out[fakeUTUN] = []netip.Addr{}
		for ip := range h.utun {
			out[fakeUTUN] = append(out[fakeUTUN], ip)
		}
	}
	return out, nil
}

// fakeDevice is a meshDevice whose Up creates the fake host's utun (carrying
// only the link address, as plumb leaves it) and whose Down destroys it with
// every address on it, as closing a utun does.
type fakeDevice struct {
	h    *utunHost
	link netip.Addr
	up   bool
	onUp func()
}

func (d *fakeDevice) Up(context.Context) error {
	if d.onUp != nil {
		d.onUp()
	}
	d.h.ops = append(d.h.ops, "device up")
	d.up, d.h.utunUp = true, true
	d.h.utun[d.link] = true
	return nil
}

func (d *fakeDevice) Apply(context.Context, mesh.Plan) error {
	d.h.ops = append(d.h.ops, "device apply")
	return nil
}

func (d *fakeDevice) Down(context.Context) error {
	d.h.ops = append(d.h.ops, "device down")
	d.up, d.h.utunUp = false, false
	d.h.utun = map[netip.Addr]bool{}
	return nil
}

func (d *fakeDevice) WithdrawIface(context.Context, string) (int, error) { return 0, nil }

func (d *fakeDevice) Interface() string {
	if !d.up {
		return ""
	}
	return fakeUTUN
}

// utunApplier is a darwinApplier for 100.64.3.0/24 wired to h.
func utunApplier(h *utunHost) *darwinApplier {
	a := newDarwinApplier(netip.MustParsePrefix("100.64.3.0/24"), quietLogger())
	a.command, a.routes, a.ifaceAddrs = h.command, h, h.ifaceAddrs
	a.newDevice = func(cfg mesh.DeviceConfig, _ *slog.Logger) meshDevice {
		return &fakeDevice{h: h, link: cfg.LinkIP}
	}
	return a
}

func sortedAddrs(set map[netip.Addr]bool) []netip.Addr {
	var out []netip.Addr
	for ip := range set {
		out = append(out, ip)
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// TestUTUNAliasPlumbing pins B453's fix on the executor: every pod address of the
// node /24 aliased on lo0 is also a point-to-point /32 alias on the mesh utun with
// the utun's own link address as destination, so a reply the kernel generates
// for a packet that arrived on the utun (a RST for a closed port, an echo reply)
// has a source address on that interface. It pins the exact alias operations for
// add, remove, utun (re)creation and the reconcile, their order (utun alias after
// the lo0 alias on add, before it on remove), and that none of them adds,
// removes or moves a route: the only route operations are the pre-existing
// blackhole clear and install around a pod alias.
func TestUTUNAliasPlumbing(t *testing.T) {
	ctx := context.Background()
	ip := netip.MustParseAddr
	const (
		link = "100.64.3.255"
		mIP  = "100.64.3.1"
	)
	addUTUN := func(a string) string {
		return "ifconfig utun7 inet " + a + " " + link + " netmask 255.255.255.255 alias"
	}
	delUTUN := func(a string) string { return "ifconfig utun7 inet " + a + " -alias" }
	meshUp := func(t *testing.T, a *darwinApplier) {
		t.Helper()
		if err := a.ConfigureMesh(ctx, "key", mesh.DefaultListenPort, mesh.Plan{}); err != nil {
			t.Fatalf("ConfigureMesh: %v", err)
		}
	}

	cases := []struct {
		name string
		// lo0 and utun seed the kernel after the setup bring-up and before the
		// recorded run.
		lo0, utun []string
		// meshUp brings the mesh up before the recorded run.
		meshUp   bool
		run      func(t *testing.T, a *darwinApplier)
		wantOps  []string
		wantLo0  []string
		wantUTUN []string // nil: the utun does not exist
	}{
		{
			name:   "add with the mesh up aliases lo0, then the utun",
			meshUp: true,
			run: func(t *testing.T, a *darwinApplier) {
				if err := a.EnsureAlias(ctx, ip("100.64.3.17")); err != nil {
					t.Fatalf("EnsureAlias: %v", err)
				}
			},
			wantOps:  []string{"route clear-blackhole 100.64.3.17", "ifconfig lo0 alias 100.64.3.17/32", addUTUN("100.64.3.17")},
			wantLo0:  []string{"100.64.3.17"},
			wantUTUN: []string{"100.64.3.17", link},
		},
		{
			name: "add with the mesh down aliases lo0 only",
			run: func(t *testing.T, a *darwinApplier) {
				if err := a.EnsureAlias(ctx, ip("100.64.3.17")); err != nil {
					t.Fatalf("EnsureAlias: %v", err)
				}
			},
			wantOps: []string{"route clear-blackhole 100.64.3.17", "ifconfig lo0 alias 100.64.3.17/32"},
			wantLo0: []string{"100.64.3.17"},
		},
		{
			name:   "remove takes the utun alias first, then lo0",
			lo0:    []string{"100.64.3.17"},
			utun:   []string{"100.64.3.17"},
			meshUp: true,
			run: func(t *testing.T, a *darwinApplier) {
				if err := a.RemoveAlias(ctx, ip("100.64.3.17")); err != nil {
					t.Fatalf("RemoveAlias: %v", err)
				}
			},
			wantOps:  []string{delUTUN("100.64.3.17"), "ifconfig lo0 -alias 100.64.3.17", "route install-blackhole 100.64.3.17"},
			wantUTUN: []string{link},
		},
		{
			name: "remove with the mesh down touches lo0 only",
			lo0:  []string{"100.64.3.17"},
			run: func(t *testing.T, a *darwinApplier) {
				if err := a.RemoveAlias(ctx, ip("100.64.3.17")); err != nil {
					t.Fatalf("RemoveAlias: %v", err)
				}
			},
			wantOps: []string{"ifconfig lo0 -alias 100.64.3.17", "route install-blackhole 100.64.3.17"},
		},
		{
			name:   "a Service VIP never goes on the utun",
			meshUp: true,
			run: func(t *testing.T, a *darwinApplier) {
				if err := a.EnsureAlias(ctx, ip("10.43.0.80")); err != nil {
					t.Fatalf("EnsureAlias: %v", err)
				}
				if err := a.RemoveAlias(ctx, ip("10.43.0.80")); err != nil {
					t.Fatalf("RemoveAlias: %v", err)
				}
			},
			wantOps:  []string{"ifconfig lo0 alias 10.43.0.80/32", "ifconfig lo0 -alias 10.43.0.80"},
			wantUTUN: []string{link},
		},
		{
			name: "a utun (re)created under live pods gets the whole set",
			// The mesh-egress address and a VIP are on lo0 too: neither is a pod
			// address, so the reconcile leaves them to their owners.
			lo0: []string{"100.64.3.17", "100.64.3.40", mIP, "10.43.0.80"},
			run: func(t *testing.T, a *darwinApplier) {
				meshUp(t, a)
				if err := a.RemoveMesh(ctx); err != nil {
					t.Fatalf("RemoveMesh: %v", err)
				}
				meshUp(t, a)
			},
			wantOps: []string{
				"device up", "device apply", addUTUN("100.64.3.17"), addUTUN("100.64.3.40"),
				"device down",
				"device up", "device apply", addUTUN("100.64.3.17"), addUTUN("100.64.3.40"),
			},
			wantLo0:  []string{"10.43.0.80", mIP, "100.64.3.17", "100.64.3.40"},
			wantUTUN: []string{"100.64.3.17", "100.64.3.40", link},
		},
		{
			name:   "a converged resync issues no alias operation",
			lo0:    []string{"100.64.3.17"},
			utun:   []string{"100.64.3.17"},
			meshUp: true,
			run:    meshUp,
			// The resync re-applies the plan and finds nothing to fix.
			wantOps:  []string{"device apply"},
			wantLo0:  []string{"100.64.3.17"},
			wantUTUN: []string{"100.64.3.17", link},
		},
		{
			name: "the reconcile removes a utun alias whose lo0 twin is gone and restores a missing one",
			// 100.64.3.17 lost its lo0 alias (a remove that failed after the utun
			// step is the converse); 100.64.3.40 is on lo0 but not on the utun. The
			// mesh-egress and link addresses on the utun are not pod addresses.
			lo0:    []string{"100.64.3.40"},
			utun:   []string{"100.64.3.17", mIP},
			meshUp: true,
			run:    meshUp,
			wantOps: []string{
				"device apply", delUTUN("100.64.3.17"), addUTUN("100.64.3.40"),
			},
			wantLo0:  []string{"100.64.3.40"},
			wantUTUN: []string{mIP, "100.64.3.40", link},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newUTUNHost()
			a := utunApplier(h)
			if c.meshUp {
				meshUp(t, a)
			}
			for _, s := range c.lo0 {
				h.lo0[ip(s)] = true
			}
			for _, s := range c.utun {
				h.utun[ip(s)] = true
			}
			h.ops = nil
			c.run(t, a)
			if !slices.Equal(h.ops, c.wantOps) {
				t.Fatalf("ops =\n  %q\nwant\n  %q", h.ops, c.wantOps)
			}
			var wantLo0, wantUTUN []netip.Addr
			for _, s := range c.wantLo0 {
				wantLo0 = append(wantLo0, ip(s))
			}
			for _, s := range c.wantUTUN {
				wantUTUN = append(wantUTUN, ip(s))
			}
			slices.SortFunc(wantLo0, netip.Addr.Compare)
			slices.SortFunc(wantUTUN, netip.Addr.Compare)
			if got := sortedAddrs(h.lo0); !slices.Equal(got, wantLo0) {
				t.Errorf("lo0 = %v, want %v", got, wantLo0)
			}
			if got := sortedAddrs(h.utun); !slices.Equal(got, wantUTUN) {
				t.Errorf("utun = %v, want %v", got, wantUTUN)
			}
		})
	}
}

// TestUTUNAliasFailureIsReported pins that a utun alias the kernel refuses fails
// EnsureAlias loudly (the pod would answer its served ports but hang a closed
// one), while the lo0 alias, the address's home, stays in place for the retry.
func TestUTUNAliasFailureIsReported(t *testing.T) {
	ctx := context.Background()
	h := newUTUNHost()
	a := utunApplier(h)
	if err := a.ConfigureMesh(ctx, "key", mesh.DefaultListenPort, mesh.Plan{}); err != nil {
		t.Fatalf("ConfigureMesh: %v", err)
	}
	h.utunAddErr = errors.New("ioctl (SIOCAIFADDR): File exists")
	pod := netip.MustParseAddr("100.64.3.17")
	if err := a.EnsureAlias(ctx, pod); err == nil {
		t.Fatal("EnsureAlias hid a refused utun alias")
	}
	if !h.lo0[pod] {
		t.Fatal("the lo0 alias was undone by a failed utun alias")
	}
	h.utunAddErr = nil
	if err := a.EnsureAlias(ctx, pod); err != nil {
		t.Fatalf("retried EnsureAlias: %v", err)
	}
	if !h.utun[pod] {
		t.Fatal("the retry did not alias the utun")
	}
}
