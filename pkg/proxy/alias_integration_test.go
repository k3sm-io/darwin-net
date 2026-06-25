//go:build integration

// Integration tests for the real lo0 alias manager and the per-VIP 127.0.0.x
// source-identity rehearsal. These touch the live loopback interface via
// ifconfig and therefore require root; run with:
//
//	sudo CGO_ENABLED=0 go test -tags integration -run TestLo0Alias ./pkg/proxy/
//
// They are excluded from the default (rootless) test build.
package proxy

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// requireRoot skips the test when not effectively root (ifconfig alias needs it).
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root to manage lo0 aliases; run under sudo with -tags integration")
	}
}

// lo0HasAddr reports whether ip is currently present on lo0.
func lo0HasAddr(t *testing.T, ip netip.Addr) bool {
	t.Helper()
	out, err := exec.Command("ifconfig", "lo0").CombinedOutput()
	if err != nil {
		t.Fatalf("ifconfig lo0: %v: %s", err, out)
	}
	return strings.Contains(string(out), "inet "+ip.String()+" ")
}

// TestLo0AliasIdempotentLeakFree maps to acceptance M1.1-a2: lo0 alias
// create/teardown is idempotent and leak-free under churn. It Ensures the same
// address twice (idempotent create), confirms it is present on lo0, Removes it
// twice (idempotent + leak-free teardown), and confirms it is gone.
func TestLo0AliasIdempotentLeakFree(t *testing.T) {
	requireRoot(t)
	ctx := context.Background()
	mgr := newLo0AliasManager()
	// Use an address unlikely to collide with anything real.
	ip := netip.MustParseAddr("127.0.0.123")

	// Clean up no matter what.
	t.Cleanup(func() { _ = mgr.Remove(ctx, ip) })

	if lo0HasAddr(t, ip) {
		t.Fatalf("precondition: %s already on lo0", ip)
	}

	// Idempotent create: two Ensures, one resulting alias.
	if err := mgr.Ensure(ctx, ip); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	if err := mgr.Ensure(ctx, ip); err != nil {
		t.Fatalf("second Ensure (idempotent): %v", err)
	}
	if !lo0HasAddr(t, ip) {
		t.Fatalf("%s not present on lo0 after Ensure", ip)
	}

	// Idempotent + leak-free teardown: two Removes, address gone, no error.
	if err := mgr.Remove(ctx, ip); err != nil {
		t.Fatalf("first Remove: %v", err)
	}
	if err := mgr.Remove(ctx, ip); err != nil {
		t.Fatalf("second Remove (idempotent): %v", err)
	}
	if lo0HasAddr(t, ip) {
		t.Fatalf("%s leaked on lo0 after Remove", ip)
	}
}

// TestLo0AliasChurn hammers create/teardown cycles and asserts no address leaks
// after the churn settles (leak-free under churn).
func TestLo0AliasChurn(t *testing.T) {
	requireRoot(t)
	ctx := context.Background()
	mgr := newLo0AliasManager()
	ips := []netip.Addr{
		netip.MustParseAddr("127.0.0.131"),
		netip.MustParseAddr("127.0.0.132"),
		netip.MustParseAddr("127.0.0.133"),
	}
	t.Cleanup(func() {
		for _, ip := range ips {
			_ = mgr.Remove(ctx, ip)
		}
	})

	for cycle := 0; cycle < 25; cycle++ {
		for _, ip := range ips {
			if err := mgr.Ensure(ctx, ip); err != nil {
				t.Fatalf("cycle %d Ensure %s: %v", cycle, ip, err)
			}
		}
		for _, ip := range ips {
			if err := mgr.Remove(ctx, ip); err != nil {
				t.Fatalf("cycle %d Remove %s: %v", cycle, ip, err)
			}
		}
	}
	for _, ip := range ips {
		if lo0HasAddr(t, ip) {
			t.Fatalf("%s leaked after churn", ip)
		}
	}
}

// TestProxyVIPOnRealAlias is the faithful per-VIP source-identity rehearsal: the
// proxy binds a ClusterIP listener on a real lo0 alias address (a distinct
// 127.0.0.x, not 127.0.0.1) created by the real lo0AliasManager, and a client
// dialing that VIP is load-balanced to a backend. It proves the production
// alias-create -> bind-specific-address -> teardown path end to end.
func TestProxyVIPOnRealAlias(t *testing.T) {
	requireRoot(t)
	vipAddr := netip.MustParseAddr("127.0.0.140")
	vip := vipAddr.String()

	// Backend on plain loopback.
	be := newEchoBackend(t, "real-be", "127.0.0.1")
	defer be.close()
	bip, bport := be.addrPort()

	// Pre-create nothing; the proxy's real alias manager must alias the VIP so
	// the listener can bind the specific address.
	p := New(NewRoutingTable(netip.Prefix{})) // real lo0 alias manager
	t.Cleanup(func() { _ = newLo0AliasManager().Remove(context.Background(), vipAddr) })

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = p.Run(ctx) }()

	port := int32(38080)
	sp := &netv1.ServicePort{Port: port, TargetPort: 0, Protocol: netv1.ProtocolTCP}
	eps := []netv1.Endpoint{{IP: bip, Port: bport, Ready: true}}
	if err := p.Reconcile(vip, sp, eps); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// The VIP must now be aliased on lo0 and serving.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !lo0HasAddr(t, vipAddr) {
		time.Sleep(20 * time.Millisecond)
	}
	if !lo0HasAddr(t, vipAddr) {
		t.Fatalf("VIP %s was not aliased on lo0 by the proxy", vip)
	}

	c, err := net.DialTimeout("tcp", net.JoinHostPort(vip, strconv.Itoa(int(port))), 2*time.Second)
	if err != nil {
		t.Fatalf("dial VIP on real alias: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _ := c.Read(buf)
	_ = c.Close()
	if got := string(buf[:n]); got != "real-be" {
		t.Fatalf("VIP served %q, want real-be", got)
	}

	// Teardown must remove the alias (leak-free).
	p.ReconcileDelete(PortKey{ClusterIP: vip, Port: port, Protocol: netv1.ProtocolTCP})
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && lo0HasAddr(t, vipAddr) {
		time.Sleep(20 * time.Millisecond)
	}
	if lo0HasAddr(t, vipAddr) {
		t.Fatalf("VIP %s leaked on lo0 after delete", vip)
	}

	cancel()
	<-runDone
}
