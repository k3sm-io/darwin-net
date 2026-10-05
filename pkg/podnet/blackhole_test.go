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

package podnet

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// opRecorder records the ifconfig and route operations an alias manager drives,
// in order, and can be told to fail a route operation. It models lo0's alias
// list the way ifconfig reports it: -alias of an address that is not aliased
// fails.
type opRecorder struct {
	ops        []string
	clearErr   error
	installErr error
	lo0        map[string]bool
}

func (r *opRecorder) ifconfig(_ context.Context, iface, verb, arg string) error {
	r.ops = append(r.ops, "ifconfig "+iface+" "+verb+" "+arg)
	if r.lo0 == nil {
		r.lo0 = make(map[string]bool)
	}
	switch verb {
	case "alias":
		r.lo0[strings.TrimSuffix(arg, "/32")] = true
	case "-alias":
		if !r.lo0[arg] {
			return errors.New("ifconfig: ioctl (SIOCDIFADDR): Can't assign requested address")
		}
		delete(r.lo0, arg)
	}
	return nil
}

func (r *opRecorder) Install(_ context.Context, ip netip.Addr) error {
	r.ops = append(r.ops, "install-blackhole "+ip.String())
	return r.installErr
}

func (r *opRecorder) Clear(_ context.Context, ip netip.Addr) error {
	r.ops = append(r.ops, "clear-blackhole "+ip.String())
	return r.clearErr
}

// newRecordedAliasManager returns a lo0AliasManager for nodeCIDR whose ifconfig
// and route operations go to a fresh recorder.
func newRecordedAliasManager(nodeCIDR netip.Prefix) (*lo0AliasManager, *opRecorder) {
	rec := &opRecorder{}
	m := newLo0AliasManager(nodeCIDR)
	m.ifconfig = rec.ifconfig
	m.routes = rec
	return m, rec
}

// TestAliasTeardownInstallsBlackhole pins the pod-alias teardown ordering: a
// removed pod address is blackholed right after its alias goes (the alias's host
// route must be gone first or the add is EEXIST), a re-Remove stays a success,
// the next Ensure clears the blackhole BEFORE re-aliasing and fails if the clear
// fails, and an address outside the node's pod range is never blackholed.
func TestAliasTeardownInstallsBlackhole(t *testing.T) {
	ctx := context.Background()
	node := netip.MustParsePrefix("100.64.3.0/24")
	pod := netip.MustParseAddr("100.64.3.17")

	t.Run("remove then re-remove", func(t *testing.T) {
		m, rec := newRecordedAliasManager(node)
		if err := m.Ensure(ctx, pod); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		rec.ops = nil
		if err := m.Remove(ctx, pod); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		want := []string{"ifconfig lo0 -alias 100.64.3.17", "install-blackhole 100.64.3.17"}
		if !slices.Equal(rec.ops, want) {
			t.Fatalf("Remove ops = %q, want %q", rec.ops, want)
		}
		rec.ops = nil
		if err := m.Remove(ctx, pod); err != nil {
			t.Fatalf("re-Remove: %v (must be idempotent)", err)
		}
		if n := countPrefix(rec.ops, "install-blackhole"); n > 1 {
			t.Fatalf("re-Remove ops = %q: more than one install", rec.ops)
		}
	})

	t.Run("ensure clears the blackhole before aliasing", func(t *testing.T) {
		m, rec := newRecordedAliasManager(node)
		if err := m.Ensure(ctx, pod); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		want := []string{"clear-blackhole 100.64.3.17", "ifconfig lo0 alias 100.64.3.17/32"}
		if !slices.Equal(rec.ops, want) {
			t.Fatalf("Ensure ops = %q, want %q", rec.ops, want)
		}
	})

	t.Run("a failed clear fails ensure and plumbs nothing", func(t *testing.T) {
		m, rec := newRecordedAliasManager(node)
		rec.clearErr = errors.New("routing socket refused")
		if err := m.Ensure(ctx, pod); err == nil {
			t.Fatal("Ensure succeeded although the stale blackhole could not be cleared")
		}
		if n := countPrefix(rec.ops, "ifconfig"); n != 0 {
			t.Fatalf("Ensure ran ifconfig after a failed clear: %q", rec.ops)
		}
		if _, tracked := m.aliased[pod]; tracked {
			t.Fatal("a failed Ensure tracked the address as aliased")
		}
	})

	t.Run("a failed install is returned after the alias is gone", func(t *testing.T) {
		m, rec := newRecordedAliasManager(node)
		if err := m.Ensure(ctx, pod); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		rec.installErr = errors.New("routing socket refused")
		if err := m.Remove(ctx, pod); err == nil {
			t.Fatal("Remove hid a failed blackhole install")
		}
		// The retry converges: the address stays tracked as pending, so the retry
		// skips the -alias and runs the install again.
		rec.installErr, rec.ops = nil, nil
		if err := m.Remove(ctx, pod); err != nil {
			t.Fatalf("retried Remove: %v", err)
		}
		if want := []string{"install-blackhole 100.64.3.17"}; !slices.Equal(rec.ops, want) {
			t.Fatalf("retried Remove ops = %q, want %q", rec.ops, want)
		}
		if _, tracked := m.aliased[pod]; tracked {
			t.Fatal("the address is still tracked after the blackhole went in")
		}
	})

	t.Run("an address that was never aliased is not blackholed", func(t *testing.T) {
		m, rec := newRecordedAliasManager(node)
		if err := m.Remove(ctx, pod); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if want := []string{"ifconfig lo0 -alias 100.64.3.17"}; !slices.Equal(rec.ops, want) {
			t.Fatalf("Remove ops = %q, want %q (no blackhole for an untracked, unplumbed address)", rec.ops, want)
		}
	})

	t.Run("an alias a previous process left on lo0 is blackholed", func(t *testing.T) {
		m, rec := newRecordedAliasManager(node)
		rec.lo0 = map[string]bool{pod.String(): true}
		if err := m.Remove(ctx, pod); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		want := []string{"ifconfig lo0 -alias 100.64.3.17", "install-blackhole 100.64.3.17"}
		if !slices.Equal(rec.ops, want) {
			t.Fatalf("Remove ops = %q, want %q", rec.ops, want)
		}
	})

	t.Run("addresses outside the node pod range are never blackholed", func(t *testing.T) {
		for _, s := range []string{"10.43.0.80", "100.64.4.17", "100.64.3.1", "100.64.3.255", "127.0.0.151"} {
			m, rec := newRecordedAliasManager(node)
			ip := netip.MustParseAddr(s)
			if err := m.Ensure(ctx, ip); err != nil {
				t.Fatalf("Ensure %s: %v", s, err)
			}
			if err := m.Remove(ctx, ip); err != nil {
				t.Fatalf("Remove %s: %v", s, err)
			}
			if n := countPrefix(rec.ops, "install-blackhole") + countPrefix(rec.ops, "clear-blackhole"); n != 0 {
				t.Fatalf("%s: route ops %q, want none", s, rec.ops)
			}
		}
	})
}

// countPrefix counts the ops that start with prefix.
func countPrefix(ops []string, prefix string) int {
	n := 0
	for _, op := range ops {
		if strings.HasPrefix(op, prefix) {
			n++
		}
	}
	return n
}

// TestIsPodAddress pins the blackhole scope: the allocatable hosts of the node
// /24 and nothing else.
func TestIsPodAddress(t *testing.T) {
	node := netip.MustParsePrefix("100.64.3.0/24")
	cases := []struct {
		cidr netip.Prefix
		ip   string
		want bool
	}{
		{node, "100.64.3.2", true},
		{node, "100.64.3.254", true},
		{node, "100.64.3.0", false},
		{node, "100.64.3.1", false},
		{node, "100.64.3.255", false},
		{node, "100.64.4.2", false},
		{node, "10.43.0.10", false},
		{node, "::ffff:100.64.3.9", true},
		{netip.Prefix{}, "100.64.3.9", false},
		{netip.MustParsePrefix("100.64.0.0/16"), "100.64.3.9", false},
	}
	for _, c := range cases {
		if got := IsPodAddress(c.cidr, netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("IsPodAddress(%s, %s) = %v, want %v", c.cidr, c.ip, got, c.want)
		}
	}
}

// TestBlackholeMessage pins the routing-message encoding: the add is a static
// host route through 127.0.0.1 flagged RTF_BLACKHOLE (what route(8) builds for
// `add -host <ip> 127.0.0.1 -blackhole`); delete and get name the host only.
func TestBlackholeMessage(t *testing.T) {
	ip := netip.MustParseAddr("100.64.3.17")
	add := blackholeMessage(unix.RTM_ADD, ip, 7)
	if add.Type != unix.RTM_ADD || add.Seq != 7 || add.ID != uintptr(os.Getpid()) {
		t.Fatalf("add header = type %d seq %d id %d", add.Type, add.Seq, add.ID)
	}
	wantFlags := unix.RTF_UP | unix.RTF_STATIC | unix.RTF_HOST | unix.RTF_GATEWAY | unix.RTF_BLACKHOLE
	if add.Flags != wantFlags {
		t.Fatalf("add flags = %#x, want %#x", add.Flags, wantFlags)
	}
	if len(add.Addrs) != 2 {
		t.Fatalf("add addrs = %v, want dst and gateway only (no netmask: a host route)", add.Addrs)
	}
	if dst := add.Addrs[unix.RTAX_DST].(*xroute.Inet4Addr); netip.AddrFrom4(dst.IP) != ip {
		t.Fatalf("add dst = %v, want %s", dst.IP, ip)
	}
	if gw := add.Addrs[unix.RTAX_GATEWAY].(*xroute.Inet4Addr); gw.IP != [4]byte{127, 0, 0, 1} {
		t.Fatalf("add gateway = %v, want 127.0.0.1", gw.IP)
	}
	if _, err := add.Marshal(); err != nil {
		t.Fatalf("marshal add: %v", err)
	}
	for _, typ := range []int{unix.RTM_DELETE, unix.RTM_GET} {
		m := blackholeMessage(typ, ip, 8)
		if m.Flags&unix.RTF_HOST == 0 || len(m.Addrs) != 1 {
			t.Fatalf("type %d: flags %#x addrs %v, want a host destination only", typ, m.Flags, m.Addrs)
		}
		if _, err := m.Marshal(); err != nil {
			t.Fatalf("marshal type %d: %v", typ, err)
		}
	}
}

// TestBlackholesIn pins what List reports from a routing-table dump: blackhole
// host routes to pod addresses of the node /24, and nothing else.
func TestBlackholesIn(t *testing.T) {
	node := netip.MustParsePrefix("100.64.3.0/24")
	route := func(a [4]byte, flags int) *xroute.RouteMessage {
		return &xroute.RouteMessage{Flags: flags, Addrs: []xroute.Addr{unix.RTAX_DST: &xroute.Inet4Addr{IP: a}}}
	}
	msgs := []xroute.Message{
		route([4]byte{100, 64, 3, 17}, blackholeFlags),
		route([4]byte{100, 64, 3, 18}, unix.RTF_UP|unix.RTF_HOST),         // a live alias's host route
		route([4]byte{100, 64, 4, 17}, blackholeFlags),                    // another node's /24
		route([4]byte{100, 64, 3, 1}, blackholeFlags),                     // the mesh-egress address
		route([4]byte{100, 64, 3, 0}, unix.RTF_UP|unix.RTF_BLACKHOLE),     // a blackholed network route
		route([4]byte{100, 64, 3, 200}, unix.RTF_HOST|unix.RTF_BLACKHOLE), // another pod's blackhole
		&xroute.RouteMessage{Flags: blackholeFlags},                       // no destination
	}
	got := blackholesIn(msgs, node)
	want := []netip.Addr{netip.MustParseAddr("100.64.3.17"), netip.MustParseAddr("100.64.3.200")}
	if !slices.Equal(got, want) {
		t.Fatalf("blackholesIn = %v, want %v", got, want)
	}
	if got := blackholesIn(msgs, netip.MustParsePrefix("100.64.0.0/16")); len(got) != 0 {
		t.Fatalf("blackholesIn with a non-/24 node CIDR = %v, want none", got)
	}
}

// TestHostRouteFlags pins how an RTM_GET reply is read: only ip's own host route
// counts; the longest-prefix match the kernel returns for an address with no host
// route (an aggregate, the default route) is "no host route".
func TestHostRouteFlags(t *testing.T) {
	ip := netip.MustParseAddr("100.64.3.17")
	host := func(a [4]byte, flags int) *xroute.RouteMessage {
		return &xroute.RouteMessage{Flags: flags, Addrs: []xroute.Addr{&xroute.Inet4Addr{IP: a}}}
	}
	cases := []struct {
		name      string
		reply     *xroute.RouteMessage
		wantFound bool
		wantErr   bool
	}{
		{"own blackhole host route", host([4]byte{100, 64, 3, 17}, unix.RTF_HOST|unix.RTF_BLACKHOLE), true, false},
		{"aggregate match", host([4]byte{100, 64, 0, 0}, unix.RTF_UP), false, false},
		{"another host route", host([4]byte{100, 64, 3, 18}, unix.RTF_HOST), false, false},
		{"own address without RTF_HOST", host([4]byte{100, 64, 3, 17}, unix.RTF_UP), false, false},
		{"ESRCH reply", &xroute.RouteMessage{Err: unix.ESRCH}, false, false},
		{"other reply error", &xroute.RouteMessage{Err: unix.EPERM}, false, true},
	}
	for _, c := range cases {
		_, found, err := hostRouteFlags(c.reply, ip)
		if found != c.wantFound || (err != nil) != c.wantErr {
			t.Errorf("%s: found=%v err=%v, want found=%v err=%v", c.name, found, err, c.wantFound, c.wantErr)
		}
	}
}

// TestGuestTeardownBlackholesPublishedAddress proves a vm pod's published /32
// takes the same lo0 path as a host-process pod's through the production alias
// manager: SetupGuest clears any stale blackhole and then aliases the address,
// and Teardown removes the alias and blackholes it in that order, so a relayed
// connection still open to a departed vm pod cannot re-route onto the mesh utun.
func TestGuestTeardownBlackholesPublishedAddress(t *testing.T) {
	ctx := context.Background()
	node := netip.MustParsePrefix("100.64.3.0/24")
	m, rec := newRecordedAliasManager(node)
	n, err := New(node, withAliasManager(m))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gn, err := n.SetupGuest(ctx, "vm-pod")
	if err != nil {
		t.Fatalf("SetupGuest: %v", err)
	}
	ip := gn.PodIP.String()
	want := []string{"clear-blackhole " + ip, "ifconfig lo0 alias " + ip + "/32"}
	if !slices.Equal(rec.ops, want) {
		t.Fatalf("SetupGuest ops = %q, want %q", rec.ops, want)
	}
	rec.ops = nil
	if err := n.Teardown(ctx, "vm-pod"); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	want = []string{"ifconfig lo0 -alias " + ip, "install-blackhole " + ip}
	if !slices.Equal(rec.ops, want) {
		t.Fatalf("Teardown ops = %q, want %q", rec.ops, want)
	}
}
