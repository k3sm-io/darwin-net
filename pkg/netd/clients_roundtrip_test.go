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

package netd_test

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/mesh"
	"k3sm.io/darwin-net/pkg/netd"
	"k3sm.io/darwin-net/pkg/podnet"
	"k3sm.io/darwin-net/pkg/proxy"
)

// removedMesh reports how many RemoveMesh calls the executor saw (locked accessor
// for the mesh round-trip test).
func (f *fakePriv) removedMesh() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.meshRemoved
}

// waitFor polls cond until it holds or the deadline elapses.
func waitFor(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// TestPodnetClientRoundTrip proves the pkg/podnet netd-backed alias manager
// (selected by WithNetdHelper) round-trips Setup/Teardown to an in-process daemon:
// Setup drives EnsureAlias for a pod IP in the node /24, Teardown drives
// RemoveAlias — end-to-end wire compatibility within the repo.
func TestPodnetClientRoundTrip(t *testing.T) {
	sock, fp := startServer(t, netd.Config{NodePodCIDR: netip.MustParsePrefix("100.64.0.0/24")})

	n, err := podnet.New(netip.MustParsePrefix("100.64.0.0/24"), podnet.WithNetdHelper(sock), podnet.WithLogger(discardLogger()))
	if err != nil {
		t.Fatalf("podnet.New: %v", err)
	}
	ctx := context.Background()
	ip, err := n.Setup(ctx, "pod-a")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if got := fp.ensures(); len(got) != 1 || got[0] != ip {
		t.Fatalf("daemon ensured %v, want [%s]", got, ip)
	}
	if err := n.Teardown(ctx, "pod-a"); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if got := fp.removes(); len(got) != 1 || got[0] != ip {
		t.Fatalf("daemon removed %v, want [%s]", got, ip)
	}
}

// TestProxyClientRoundTrip proves the pkg/proxy netd-backed seams (selected by
// WithNetdHelper) round-trip to an in-process daemon: reconciling a Service on a
// privileged (<1024) VIP port drives EnsureAlias for the VIP (in the Service CIDR)
// and BindPort for the VIP:port (authorized via the PortAuthorizer, fd passed back
// over SCM_RIGHTS), and deleting it drives RemoveAlias.
func TestProxyClientRoundTrip(t *testing.T) {
	const vip = "10.43.0.42"
	sock, fp := startServer(t, netd.Config{
		NodePodCIDR:    netip.MustParsePrefix("100.64.0.0/24"),
		ServiceCIDR:    netip.MustParsePrefix("10.43.0.0/16"),
		PortAuthorizer: fakeAuthorizer{allow: map[int]bool{80: true}},
	})

	p := proxy.New(proxy.NewRoutingTable(netip.Prefix{}), proxy.WithNetdHelper(sock), proxy.WithLogger(discardLogger()))
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = p.Run(ctx) }()

	sp := &netv1.ServicePort{Port: 80, Protocol: netv1.ProtocolTCP}
	eps := []netv1.Endpoint{{IP: "100.64.0.50", Port: 8080, Ready: true}}
	if err := p.Reconcile(vip, sp, eps); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	want := netip.MustParseAddr(vip)
	wantAP := netip.MustParseAddrPort(vip + ":80")
	waitFor(t, 3*time.Second, func() bool {
		ens := fp.ensures()
		bnd := fp.boundPorts()
		return len(ens) >= 1 && ens[0] == want && len(bnd) >= 1 && bnd[0] == wantAP
	}, "proxy did not round-trip EnsureAlias + BindPort for the VIP through the daemon")

	p.ReconcileDelete(proxy.PortKey{ClusterIP: vip, Port: 80, Protocol: netv1.ProtocolTCP})
	waitFor(t, 3*time.Second, func() bool {
		rm := fp.removes()
		return len(rm) >= 1 && rm[0] == want
	}, "proxy did not round-trip RemoveAlias for the VIP through the daemon")

	cancel()
	<-runDone
}

// TestMeshClientRoundTrip proves the pkg/mesh netd-backed device (selected by
// WithNetdHelper) round-trips Start/Reconcile/Close to an in-process daemon: the
// typed peer set crosses the wire (never the rendered UAPI), the daemon
// re-validates and re-renders it, and the resulting plan routes the peer's /24.
func TestMeshClientRoundTrip(t *testing.T) {
	sock, fp := startServer(t, netd.Config{
		NodePodCIDR:     netip.MustParsePrefix("100.64.0.0/24"),
		MeshKeyResolver: fakeResolver{key: genKeyB64(t)},
	})

	m, err := mesh.New(netip.MustParsePrefix("100.64.0.0/24"),
		mesh.WithNetdHelper(sock, "node-key-ref"), mesh.WithLogger(discardLogger()))
	if err != nil {
		t.Fatalf("mesh.New: %v", err)
	}
	ctx := context.Background()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	specs := []netv1.MeshPeerSpec{{
		SchemaVersion: netv1.MeshPeerSchemaVersion,
		NodeName:      "nodeB",
		PublicKey:     genKeyB64(t),
		Endpoint:      "192.0.2.10:51820",
		PodCIDR:       "100.64.1.0/24",
		AllowedIPs:    []string{"100.64.1.0/24"},
	}}
	if err := m.Reconcile(ctx, specs); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	plans := fp.plans()
	if len(plans) < 2 {
		t.Fatalf("daemon saw %d ConfigureMesh calls, want >=2 (Start + Reconcile)", len(plans))
	}
	last := plans[len(plans)-1]
	if len(last.Peers) != 1 || len(last.Routes) != 1 || last.Routes[0].String() != "100.64.1.0/24" {
		t.Fatalf("reconciled plan = %+v, want 1 peer routing 100.64.1.0/24", last)
	}

	if err := m.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := fp.removedMesh(); got != 1 {
		t.Fatalf("RemoveMesh called %d times, want 1", got)
	}
}
