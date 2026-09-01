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
	"strings"
	"testing"
)

// fakeRouteTable is the kernel routing table as a test double. It separates what a
// caller ASKED for (adds/deletes, recorded) from what the table actually HOLDS
// (table), which is the whole distinction the read-back exists to make: dropAdds
// reproduces the live macOS failure where route(8) reports a successful add,
// exits 0, and the kernel installs nothing.
type fakeRouteTable struct {
	table    []Route
	adds     []Route
	deletes  []Route
	dropAdds bool // accept every add, install nothing (the observed macOS behaviour)
	dropDels bool // accept every delete, remove nothing
	addOut   string
	addErr   error
	listErr  error
}

func (f *fakeRouteTable) Add(_ context.Context, prefix netip.Prefix, iface string) (string, error) {
	f.adds = append(f.adds, Route{Prefix: prefix, Interface: iface})
	if !f.dropAdds {
		f.table = append(f.table, Route{Prefix: prefix, Interface: iface})
	}
	return f.addOut, f.addErr
}

func (f *fakeRouteTable) Delete(_ context.Context, prefix netip.Prefix, iface string) (string, error) {
	f.deletes = append(f.deletes, Route{Prefix: prefix, Interface: iface})
	if f.dropDels {
		return "", nil
	}
	kept := f.table[:0]
	for _, r := range f.table {
		if r.Prefix == prefix && r.Interface == iface {
			continue
		}
		kept = append(kept, r)
	}
	f.table = kept
	return "", nil
}

func (f *fakeRouteTable) List(context.Context) ([]Route, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]Route, len(f.table))
	copy(out, f.table)
	return out, nil
}

// routeDevice returns a WGDevice wired to fake, with the interface name already
// resolved, so the route reconcile can be driven without privilege (no utun, no
// wireguard: reconcileRoutes touches neither).
func routeDevice(fake *fakeRouteTable) *WGDevice {
	d := newWGDevice(wgLink{name: "utun", mtu: MTU, mss: MSSClamp, listenPort: DefaultListenPort}, discardLogger())
	d.rt = fake
	d.iface = "utun9"
	return d
}

func mustPrefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		out[i] = p.Masked()
	}
	return out
}

// TestReconcileRoutesFailsLoudlyWhenTheKernelDropsTheAdd is the regression test for
// the defect this file exists for: on macOS, `route -n add -net <cidr> -interface
// <utun>` against an ADDRESSLESS utun is rejected by the kernel with ENETUNREACH,
// route(8) prints "writing to routing socket: Network is unreachable" — and exits
// 0. The old applier trusted that exit status, recorded the route as installed and
// logged "routes=1" while the kernel table held nothing, so every packet for the
// peer's pods went to the host's default gateway. The apply must instead fail, and
// must not claim ownership of a route that is not there.
func TestReconcileRoutesFailsLoudlyWhenTheKernelDropsTheAdd(t *testing.T) {
	fake := &fakeRouteTable{
		dropAdds: true,
		addOut:   "route: writing to routing socket: Network is unreachable\nadd net 100.64.1.0: gateway utun9: Network is unreachable",
	}
	d := routeDevice(fake)

	n, err := d.reconcileRoutes(context.Background(), mustPrefixes(t, "100.64.1.0/24"))
	if err == nil {
		t.Fatalf("reconcileRoutes reported %d installed routes and no error, but the kernel table is empty (the exact lie this test pins)", n)
	}
	if !errors.Is(err, ErrRouteNotInstalled) {
		t.Fatalf("error = %v, want one wrapping ErrRouteNotInstalled", err)
	}
	if !strings.Contains(err.Error(), "100.64.1.0/24") {
		t.Errorf("error %q does not name the missing prefix", err)
	}
	if !strings.Contains(err.Error(), "Network is unreachable") {
		t.Errorf("error %q does not quote route(8)'s own report, so an operator cannot see WHY it failed", err)
	}
	if len(d.routes) != 0 {
		t.Errorf("device claims %v as installed routes after a failed apply", d.routes)
	}
}

// TestReconcileRoutesRecordsOnlyVerifiedRoutes pins the positive half: routes the
// kernel really holds are counted and owned, the bookkeeping is re-derived from
// the table (not from the commands issued), and a second apply is a no-op because
// the routes are already verified.
func TestReconcileRoutesRecordsOnlyVerifiedRoutes(t *testing.T) {
	fake := &fakeRouteTable{}
	d := routeDevice(fake)
	want := mustPrefixes(t, "100.64.1.0/24", "100.64.2.0/24")

	n, err := d.reconcileRoutes(context.Background(), want)
	if err != nil {
		t.Fatalf("reconcileRoutes: %v", err)
	}
	if n != 2 {
		t.Fatalf("installed = %d, want 2", n)
	}
	for _, p := range want {
		if _, ok := d.routes[p]; !ok {
			t.Errorf("route %s missing from the device's verified set %v", p, d.routes)
		}
	}

	adds := len(fake.adds)
	if n, err := d.reconcileRoutes(context.Background(), want); err != nil || n != 2 {
		t.Fatalf("second reconcileRoutes = (%d, %v), want (2, nil)", n, err)
	}
	if len(fake.adds) != adds {
		t.Errorf("second apply re-issued adds %v; an already-verified route must not be re-added", fake.adds[adds:])
	}
}

// TestReconcileRoutesRejectsARouteOnAnotherInterface pins that the read-back is
// interface-scoped. A prefix present in the table but bound elsewhere (the host's
// LAN interface, a stale tunnel) does NOT satisfy the mesh's route: traffic would
// leave the wrong link, which is the same blackhole as no route at all.
func TestReconcileRoutesRejectsARouteOnAnotherInterface(t *testing.T) {
	want := mustPrefixes(t, "100.64.1.0/24")
	fake := &fakeRouteTable{
		dropAdds: true,
		table:    []Route{{Prefix: want[0], Interface: "en0"}},
	}
	d := routeDevice(fake)

	if _, err := d.reconcileRoutes(context.Background(), want); !errors.Is(err, ErrRouteNotInstalled) {
		t.Fatalf("error = %v, want ErrRouteNotInstalled for a route bound to en0 instead of the utun", err)
	}
}

// TestReconcileRoutesWithdrawsDepartedPeerRoutes pins the removal half of the
// reconcile: a peer that leaves the plan has its route deleted and dropped from
// the verified set, so it stops stealing traffic.
func TestReconcileRoutesWithdrawsDepartedPeerRoutes(t *testing.T) {
	fake := &fakeRouteTable{}
	d := routeDevice(fake)
	two := mustPrefixes(t, "100.64.1.0/24", "100.64.2.0/24")
	if _, err := d.reconcileRoutes(context.Background(), two); err != nil {
		t.Fatalf("reconcileRoutes: %v", err)
	}

	n, err := d.reconcileRoutes(context.Background(), two[:1])
	if err != nil {
		t.Fatalf("reconcileRoutes after departure: %v", err)
	}
	if n != 1 {
		t.Fatalf("installed = %d, want 1", n)
	}
	if _, ok := d.routes[two[1]]; ok {
		t.Errorf("departed peer route %s is still owned: %v", two[1], d.routes)
	}
	if len(fake.deletes) != 1 || fake.deletes[0].Prefix != two[1] {
		t.Errorf("deletes = %v, want exactly the departed peer's %s", fake.deletes, two[1])
	}
}

// TestReconcileRoutesKeepsRetryingALingeringStaleRoute pins the deliberate
// asymmetry: a route that is wanted but absent fails the apply, while a route that
// should have gone but is still in the table only warns — the desired state IS
// programmed, so wedging the mesh over it would be worse than the leak. It stays
// owned so the next apply retries the delete rather than forgetting it.
func TestReconcileRoutesKeepsRetryingALingeringStaleRoute(t *testing.T) {
	fake := &fakeRouteTable{}
	d := routeDevice(fake)
	two := mustPrefixes(t, "100.64.1.0/24", "100.64.2.0/24")
	if _, err := d.reconcileRoutes(context.Background(), two); err != nil {
		t.Fatalf("reconcileRoutes: %v", err)
	}

	fake.dropDels = true
	n, err := d.reconcileRoutes(context.Background(), two[:1])
	if err != nil {
		t.Fatalf("a lingering stale route must not fail the apply: %v", err)
	}
	if n != 1 {
		t.Fatalf("installed = %d, want 1 (the stale route is not counted as a peer route)", n)
	}
	if _, ok := d.routes[two[1]]; !ok {
		t.Fatalf("the stale route was forgotten, so no later apply will ever remove it")
	}

	deletes := len(fake.deletes)
	if _, err := d.reconcileRoutes(context.Background(), two[:1]); err != nil {
		t.Fatalf("reconcileRoutes: %v", err)
	}
	if len(fake.deletes) != deletes+1 {
		t.Errorf("the next apply did not retry the stale delete (deletes %d -> %d)", deletes, len(fake.deletes))
	}
}

// TestReconcileRoutesFailsWhenTheTableCannotBeRead pins that an unreadable kernel
// table is a failure, not an assumption of success: with no read-back there is no
// evidence, and reporting installed routes without evidence is the defect.
func TestReconcileRoutesFailsWhenTheTableCannotBeRead(t *testing.T) {
	fake := &fakeRouteTable{listErr: errors.New("sysctl: operation not permitted")}
	d := routeDevice(fake)

	if _, err := d.reconcileRoutes(context.Background(), mustPrefixes(t, "100.64.1.0/24")); err == nil {
		t.Fatal("reconcileRoutes reported success without being able to read the routing table")
	}
}

// TestPrefixesOn pins the interface-scoping helper the read-back is built on.
func TestPrefixesOn(t *testing.T) {
	p := mustPrefixes(t, "100.64.1.0/24", "100.64.2.0/24", "0.0.0.0/0")
	have := []Route{
		{Prefix: p[0], Interface: "utun9"},
		{Prefix: p[1], Interface: "en0"},
		{Prefix: p[2], Interface: "en0"},
	}
	on := prefixesOn(have, "utun9")
	if len(on) != 1 {
		t.Fatalf("prefixesOn(utun9) = %v, want exactly the one utun9 route", on)
	}
	if _, ok := on[p[0]]; !ok {
		t.Errorf("prefixesOn(utun9) = %v, want %s", on, p[0])
	}
}

// TestSortedPrefixes pins the deterministic command order the reconcile issues its
// route mutations and reports its divergences in.
func TestSortedPrefixes(t *testing.T) {
	p := mustPrefixes(t, "100.64.3.0/24", "100.64.1.0/24", "100.64.2.0/24")
	set := map[netip.Prefix]struct{}{p[0]: {}, p[1]: {}, p[2]: {}}
	got := sortedPrefixes(set)
	want := []netip.Prefix{p[1], p[2], p[0]}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sortedPrefixes = %v, want %v", got, want)
		}
	}
}
