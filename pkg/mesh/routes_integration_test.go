//go:build integration

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
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"k3sm.io/darwin-net/pkg/podnet"
)

// The test node's /24. It is deliberately not 100.64.0.0/24 (which
// TestMeshDeviceBringUpOnRealUTUN uses) so the two root-gated tests never contend
// for the same lo0 alias or the same route.
var (
	routeTestSelf    = netip.MustParsePrefix("100.66.0.0/24")
	routeTestPeer    = netip.MustParsePrefix("100.66.9.0/24")
	routeTestPeerSrc = netip.MustParseAddr("100.66.9.5")
)

// TestKernelRoutesLandOnlyWithAUTUNAddress is the hardware-level root-cause pin for
// the defect the mesh shipped with: a per-peer route bound to an ADDRESSLESS utun
// is rejected by the kernel with ENETUNREACH, while route(8) prints its complaint
// and STILL EXITS 0 — so an applier that trusted the exit status logged
// "routes=1" with an empty kernel table and sent every cross-node packet to the
// host's default gateway.
//
// It asserts both halves against the real kernel: addressless -> the route is
// absent from the table read-back; with the utun carrying podnet.MeshLinkIP -> the
// same command lands and the read-back proves it. It is root-gated (t.Skip without
// root) and does NOT run in the unit pass.
func TestKernelRoutesLandOnlyWithAUTUNAddress(t *testing.T) {
	requireRoot(t)
	ctx := context.Background()
	rt := kernelRouteTable{}

	_, iface := newTestUTUN(t)

	// (1) Addressless: route(8) may or may not complain, but the kernel table is
	// the verdict, and it must NOT hold the route.
	report, _ := rt.Add(ctx, routeTestPeer, iface)
	t.Logf("addressless add reported: %q", report)
	if routeIsOn(t, rt, routeTestPeer, iface) {
		t.Fatalf("a route landed on the addressless %s; this test's premise (and the fix it guards) no longer holds", iface)
	}

	// (2) With the utun carrying its own point-to-point address, the same add lands.
	linkIP, err := podnet.MeshLinkIP(routeTestSelf)
	if err != nil {
		t.Fatalf("MeshLinkIP: %v", err)
	}
	mustRun(t, "ifconfig", iface, "inet", linkIP.String(), linkIP.String(), "netmask", "255.255.255.255", "up")
	if report, err := rt.Add(ctx, routeTestPeer, iface); err != nil {
		t.Fatalf("add %s -> %s: %v (%s)", routeTestPeer, iface, err, report)
	}
	t.Cleanup(func() { _, _ = rt.Delete(context.Background(), routeTestPeer, iface) })
	if !routeIsOn(t, rt, routeTestPeer, iface) {
		t.Fatalf("route %s is absent from the kernel table on %s even with the link address %s assigned", routeTestPeer, iface, linkIP)
	}

	// (3) The read-back also refuses the wrong interface: the same prefix is not
	// reported on lo0, so a route that landed elsewhere can never satisfy the mesh.
	if routeIsOn(t, rt, routeTestPeer, "lo0") {
		t.Fatalf("route %s is reported on lo0; the read-back is not interface-scoped", routeTestPeer)
	}

	// (4) Deleting it removes it from the table, so teardown is leak-free.
	if _, err := rt.Delete(ctx, routeTestPeer, iface); err != nil {
		t.Fatalf("delete %s -> %s: %v", routeTestPeer, iface, err)
	}
	if routeIsOn(t, rt, routeTestPeer, iface) {
		t.Fatalf("route %s survived its delete on %s", routeTestPeer, iface)
	}
}

// TestInboundTunnelTrafficToTheMeshIPIsAnswered pins the local-delivery half of the
// datapath against the real kernel: with the mesh-egress source on lo0 and the peer
// route on the utun, an ICMP echo request that arrives ON THE UTUN addressed to
// this node's mesh IP is delivered, answered, and the reply is routed back OUT the
// utun. It reproduces the live-lab symptom (a decrypted echo request drew no reply)
// and pins its actual cause: the reply path needs the peer route, which never
// landed. It also pins the address placement — the mesh IP must stay on lo0, since
// an address on the utun is reached over the utun and stops being loopback-dialable
// by the node's own processes.
//
// The utun here is bare (no wireguard), which is exactly what makes the assertion
// possible: a packet written to the tun fd is what wireguard would hand the kernel
// after decryption. Cross-node reachability between two real Macs remains the
// two-Mac lab gate's job.
func TestInboundTunnelTrafficToTheMeshIPIsAnswered(t *testing.T) {
	requireRoot(t)
	ctx := context.Background()
	rt := kernelRouteTable{}

	dev, iface := newTestUTUN(t)

	linkIP, err := podnet.MeshLinkIP(routeTestSelf)
	if err != nil {
		t.Fatalf("MeshLinkIP: %v", err)
	}
	meshIP, err := podnet.MeshEgressIP(routeTestSelf)
	if err != nil {
		t.Fatalf("MeshEgressIP: %v", err)
	}
	mustRun(t, "ifconfig", iface, "inet", linkIP.String(), linkIP.String(), "netmask", "255.255.255.255", "up")
	mustRun(t, "ifconfig", "lo0", "alias", meshIP.String()+"/32")
	t.Cleanup(func() { _ = exec.Command("ifconfig", "lo0", "-alias", meshIP.String()).Run() })

	if _, err := rt.Add(ctx, routeTestPeer, iface); err != nil {
		t.Fatalf("add peer route: %v", err)
	}
	t.Cleanup(func() { _, _ = rt.Delete(context.Background(), routeTestPeer, iface) })
	if !routeIsOn(t, rt, routeTestPeer, iface) {
		t.Fatalf("peer route %s did not land on %s", routeTestPeer, iface)
	}

	// The mesh IP stays locally bindable and loopback-dialable (the node's control
	// plane listens on it); an address moved onto the utun would not be.
	ln, err := net.Listen("tcp", net.JoinHostPort(meshIP.String(), "0"))
	if err != nil {
		t.Fatalf("bind the mesh IP: %v", err)
	}
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("same-node dial of the mesh IP %s: %v (the mesh IP is no longer loopback-reachable)", ln.Addr(), err)
	}
	_ = conn.Close()
	_ = ln.Close()

	replies := make(chan []byte, 4)
	go func() {
		bufs := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		for {
			n, err := dev.Read(bufs, sizes, 4)
			if err != nil {
				return
			}
			if n > 0 {
				p := make([]byte, sizes[0])
				copy(p, bufs[0][4:4+sizes[0]])
				replies <- p
			}
		}
	}()

	req := icmpEchoRequest(routeTestPeerSrc, meshIP)
	frame := make([]byte, 4+len(req))
	copy(frame[4:], req)
	if _, err := dev.Write([][]byte{frame}, 4); err != nil {
		t.Fatalf("inject the decrypted echo request: %v", err)
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case p := <-replies:
			if len(p) < 21 || p[9] != 1 /* ICMP */ || p[20] != 0 /* echo reply */ {
				continue // unrelated traffic on the tunnel
			}
			src, _ := netip.AddrFromSlice(p[12:16])
			dst, _ := netip.AddrFromSlice(p[16:20])
			if src != meshIP || dst != routeTestPeerSrc {
				t.Fatalf("echo reply src/dst = %s -> %s, want %s -> %s", src, dst, meshIP, routeTestPeerSrc)
			}
			return
		case <-deadline:
			t.Fatalf("no ICMP echo reply left %s within 5s: an echo request that arrived on the tunnel for this node's mesh IP %s was not answered", iface, meshIP)
		}
	}
}

// requireRoot skips a test that cannot run unprivileged.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root: creates a utun, assigns addresses, installs kernel routes")
	}
}

// newTestUTUN creates a real utun for the duration of the test and returns it with
// its resolved name. Closing the tun destroys the interface, and with it every
// address and route the test put on it.
func newTestUTUN(t *testing.T) (tun.Device, string) {
	t.Helper()
	dev, err := tun.CreateTUN("utun", MTU)
	if err != nil {
		t.Fatalf("create utun: %v", err)
	}
	t.Cleanup(func() { _ = dev.Close() })
	name, err := dev.Name()
	if err != nil {
		t.Fatalf("resolve utun name: %v", err)
	}
	return dev, name
}

// routeIsOn reports whether the kernel's own routing table currently holds prefix
// bound to iface. It is the read-back the applier trusts, exercised here against
// the real kernel.
func routeIsOn(t *testing.T, rt kernelRouteTable, prefix netip.Prefix, iface string) bool {
	t.Helper()
	have, err := rt.List(context.Background())
	if err != nil {
		t.Fatalf("list kernel routes: %v", err)
	}
	_, ok := prefixesOn(have, iface)[prefix.Masked()]
	return ok
}

// mustRun runs a privileged setup command, failing the test with its output.
func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
}

// icmpEchoRequest builds a complete IPv4 ICMP echo request, the packet wireguard
// hands the kernel after decrypting a peer's ping of this node's mesh IP.
func icmpEchoRequest(src, dst netip.Addr) []byte {
	icmp := make([]byte, 16)
	icmp[0] = 8 // echo request
	binary.BigEndian.PutUint16(icmp[4:], 0x6b33)
	binary.BigEndian.PutUint16(icmp[6:], 1)
	copy(icmp[8:], "k3sm-mesh")
	binary.BigEndian.PutUint16(icmp[2:], onesComplementChecksum(icmp))

	ip := make([]byte, 20)
	ip[0] = 0x45 // IPv4, 5-word header
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)+len(icmp)))
	binary.BigEndian.PutUint16(ip[4:], 0x6b33)
	ip[8] = 64 // TTL
	ip[9] = 1  // ICMP
	s, d := src.As4(), dst.As4()
	copy(ip[12:], s[:])
	copy(ip[16:], d[:])
	binary.BigEndian.PutUint16(ip[10:], onesComplementChecksum(ip))
	return append(ip, icmp...)
}

// onesComplementChecksum is the internet checksum (RFC 1071) over b.
func onesComplementChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
