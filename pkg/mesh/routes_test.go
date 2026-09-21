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
	"net"
	"net/netip"
	"strings"
	"testing"

	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// fakeRouteTable is the kernel routing table as a test double. It separates what a
// caller ASKED for (adds/deletes, recorded) from what the table actually HOLDS
// (table), which is the whole distinction the read-back exists to make: dropAdds
// reproduces the live macOS failure where the add is refused (or reported done)
// and the kernel installs nothing.
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
// the defect this file exists for: on macOS an RTM_ADD for a route bound to an
// ADDRESSLESS utun is rejected by the kernel with ENETUNREACH and nothing lands.
// The applier once drove route(8), which prints that refusal and exits 0; it
// trusted the exit status, recorded the route as installed and logged "routes=1"
// while the kernel table held nothing, so every packet for the peer's pods went to
// the host's default gateway. The apply must instead fail on what the table holds,
// whatever the mutation reported, and must not claim ownership of a route that is
// not there.
func TestReconcileRoutesFailsLoudlyWhenTheKernelDropsTheAdd(t *testing.T) {
	fake := &fakeRouteTable{
		dropAdds: true,
		addOut:   "RTM_ADD 100.64.1.0/24 -interface utun9: network is unreachable",
		addErr:   unix.ENETUNREACH,
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
	if !strings.Contains(err.Error(), "network is unreachable") {
		t.Errorf("error %q does not quote the routing socket's own report, so an operator cannot see WHY it failed", err)
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

// TestRouteMessageEncodesAnInterfaceRoute pins the routing message the production
// table writes, decoded back through the same parser the read-back uses: an
// RTM_ADD / RTM_DELETE that is RTF_UP|RTF_STATIC and nothing else (no RTF_GATEWAY:
// the next hop is the link; no RTF_HOST: the netmask is the width), whose
// destination is the masked prefix, whose netmask is the prefix length, and whose
// gateway is the interface's own AF_LINK address carrying its index. This is the
// message route(8) builds for `-net <prefix> -interface <iface>`, so the kernel
// sees the same request it did before the exec was removed.
func TestRouteMessageEncodesAnInterfaceRoute(t *testing.T) {
	cases := []struct {
		name   string
		typ    int
		prefix string
		bits   int
		mask   [4]byte
	}{
		{"add /24", unix.RTM_ADD, "100.64.1.7/24", 24, [4]byte{255, 255, 255, 0}},
		{"delete /24", unix.RTM_DELETE, "100.64.2.0/24", 24, [4]byte{255, 255, 255, 0}},
		{"add /32", unix.RTM_ADD, "100.64.3.9/32", 32, [4]byte{255, 255, 255, 255}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prefix := netip.MustParsePrefix(tc.prefix)
			b, err := routeMessage(tc.typ, prefix, "utun9", 21).Marshal()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			msgs, err := xroute.ParseRIB(xroute.RIBTypeRoute, b)
			if err != nil {
				t.Fatalf("parse the marshalled message back: %v", err)
			}
			if len(msgs) != 1 {
				t.Fatalf("parsed %d messages, want 1", len(msgs))
			}
			rm, ok := msgs[0].(*xroute.RouteMessage)
			if !ok {
				t.Fatalf("parsed %T, want *route.RouteMessage", msgs[0])
			}
			if rm.Type != tc.typ {
				t.Errorf("type = %d, want %d", rm.Type, tc.typ)
			}
			if rm.Flags != unix.RTF_UP|unix.RTF_STATIC {
				t.Errorf("flags = %#x, want RTF_UP|RTF_STATIC (%#x) and nothing else", rm.Flags, unix.RTF_UP|unix.RTF_STATIC)
			}
			if len(rm.Addrs) <= unix.RTAX_NETMASK {
				t.Fatalf("addrs = %v, want dst, gateway and netmask", rm.Addrs)
			}
			dst, ok := rm.Addrs[unix.RTAX_DST].(*xroute.Inet4Addr)
			if !ok || dst.IP != prefix.Masked().Addr().As4() {
				t.Errorf("dst = %+v, want the masked prefix address %s", rm.Addrs[unix.RTAX_DST], prefix.Masked().Addr())
			}
			gw, ok := rm.Addrs[unix.RTAX_GATEWAY].(*xroute.LinkAddr)
			if !ok || gw.Index != 21 {
				t.Errorf("gateway = %+v, want the AF_LINK address of interface index 21", rm.Addrs[unix.RTAX_GATEWAY])
			}
			mask, ok := rm.Addrs[unix.RTAX_NETMASK].(*xroute.Inet4Addr)
			if !ok || mask.IP != tc.mask {
				t.Errorf("netmask = %+v, want %v", rm.Addrs[unix.RTAX_NETMASK], tc.mask)
			}
			// The read-back decodes this message to exactly the Route the applier
			// will look for, so the write and the verification agree on the key.
			if p, ok := routeMessagePrefix(rm); !ok || p != netip.PrefixFrom(prefix.Masked().Addr(), tc.bits) {
				t.Errorf("read-back decodes the message as %v (%v), want %s", p, ok, prefix.Masked())
			}
		})
	}
}

// TestKernelRouteTableReportsTheKernelsVerdict pins the errno mapping of the
// production table with the socket write recorded: an accepted write is reported
// as such; a refused add surfaces the kernel's errno (ENETUNREACH on an addressless
// utun, EEXIST for a route the table already holds) rather than swallowing it,
// since the read-back needs to tell an add that landed elsewhere from one that
// landed here; a delete of a route that is already gone (ESRCH) is not an error,
// so teardown stays idempotent; any other refusal of a delete is. In every case
// the report names the request and the bytes written are the message routeMessage
// builds, addressed to the interface's real index.
func TestKernelRouteTableReportsTheKernelsVerdict(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skipf("no lo0 to resolve an interface index against: %v", err)
	}
	prefix := netip.MustParsePrefix("100.64.1.0/24")
	cases := []struct {
		name    string
		del     bool
		errno   error
		wantErr error // nil: the call must succeed
		typ     int
	}{
		{"add accepted", false, nil, nil, unix.RTM_ADD},
		{"add refused on an addressless link", false, unix.ENETUNREACH, unix.ENETUNREACH, unix.RTM_ADD},
		{"add of a route the table already holds", false, unix.EEXIST, unix.EEXIST, unix.RTM_ADD},
		{"delete accepted", true, nil, nil, unix.RTM_DELETE},
		{"delete of a route already gone", true, unix.ESRCH, nil, unix.RTM_DELETE},
		{"delete refused", true, unix.EPERM, unix.EPERM, unix.RTM_DELETE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var written [][]byte
			rt := kernelRouteTable{write: func(b []byte) error {
				written = append(written, b)
				return tc.errno
			}}
			var (
				report string
				err    error
			)
			if tc.del {
				report, err = rt.Delete(context.Background(), prefix, lo.Name)
			} else {
				report, err = rt.Add(context.Background(), prefix, lo.Name)
			}
			if tc.wantErr == nil && err != nil {
				t.Fatalf("err = %v, want nil (report %q)", err, report)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want one wrapping %v (report %q)", err, tc.wantErr, report)
			}
			if tc.errno == nil && !strings.HasSuffix(report, ": accepted") {
				t.Errorf("report %q does not say the kernel accepted the request", report)
			}
			if !strings.Contains(report, prefix.String()) || !strings.Contains(report, lo.Name) {
				t.Errorf("report %q does not name the prefix and interface of the request", report)
			}
			if len(written) != 1 {
				t.Fatalf("wrote %d messages, want exactly 1", len(written))
			}
			msgs, err := xroute.ParseRIB(xroute.RIBTypeRoute, written[0])
			if err != nil || len(msgs) != 1 {
				t.Fatalf("parse the written message: %v (%d messages)", err, len(msgs))
			}
			rm := msgs[0].(*xroute.RouteMessage)
			if rm.Type != tc.typ {
				t.Errorf("wrote type %d, want %d", rm.Type, tc.typ)
			}
			gw, ok := rm.Addrs[unix.RTAX_GATEWAY].(*xroute.LinkAddr)
			if !ok || gw.Index != lo.Index {
				t.Errorf("wrote gateway %+v, want the AF_LINK address of %s (index %d)", rm.Addrs[unix.RTAX_GATEWAY], lo.Name, lo.Index)
			}
		})
	}
}

// TestKernelRouteTableRefusesAnUnknownInterface pins that a request for an
// interface the host does not have fails before anything is written: there is no
// index to bind the route to, and a message with index 0 would ask the kernel to
// pick a link.
func TestKernelRouteTableRefusesAnUnknownInterface(t *testing.T) {
	rt := kernelRouteTable{write: func([]byte) error {
		t.Fatal("a routing message was written for an interface that does not exist")
		return nil
	}}
	if _, err := rt.Add(context.Background(), netip.MustParsePrefix("100.64.1.0/24"), "utun999"); err == nil {
		t.Fatal("Add on a nonexistent interface returned no error")
	}
}
