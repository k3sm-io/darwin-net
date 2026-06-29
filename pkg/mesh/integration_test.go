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
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"os"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// genWGKeyB64 returns a random 32-byte wireguard key, base64-encoded. The
// integration smoke test only needs well-formed keys; a real handshake is the
// two-Mac lab gate's job.
func genWGKeyB64(t *testing.T) string {
	t.Helper()
	var k [wgKeyBytes]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

// TestMeshDeviceBringUpOnRealUTUN exercises the real, privileged datapath: it
// creates a utun, runs wireguard over it, plumbs the mesh-egress lo0 alias, loads
// the utun-scoped MSS-clamp pf anchor, installs a peer route, reconverges on an
// endpoint change, and tears it all down leak-free. It is root-gated (t.Skip
// without root) and does NOT run in the unit pass.
//
// It proves the LOCAL bring-up only. Cross-node reachability — two real Macs
// reaching each other's pod IPs (iperf3 both directions), bounce-a-node ->
// reconverge — is the two-Mac lab gate (K3SM_LAB=1), which a single host cannot
// assert.
func TestMeshDeviceBringUpOnRealUTUN(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root: creates a utun, installs kernel routes, loads a pf anchor")
	}

	self := netip.MustParsePrefix("100.64.0.0/24")
	m, err := New(self,
		WithPrivateKey(genWGKeyB64(t)),
		WithListenPort(51821), // avoid colliding with a real wireguard on 51820
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start (utun + wireguard + pf): %v", err)
	}
	defer func() {
		if err := m.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	if got := m.MeshIP().String(); got != "100.64.0.1" {
		t.Fatalf("MeshIP = %s, want 100.64.0.1", got)
	}

	peer := netv1.MeshPeerSpec{
		NodeName:   "peer-1",
		PublicKey:  genWGKeyB64(t),
		Endpoint:   "203.0.113.7:51820",
		PodCIDR:    "100.64.1.0/24",
		AllowedIPs: []string{"100.64.1.0/24"},
	}.WithDefaults()
	if err := m.Reconcile(ctx, []netv1.MeshPeerSpec{peer}); err != nil {
		t.Fatalf("Reconcile (install peer route): %v", err)
	}

	// Reconverge on a live endpoint change (the roam/wake path), not a restart.
	peer.Endpoint = "203.0.113.8:51820"
	if err := m.Reconcile(ctx, []netv1.MeshPeerSpec{peer.WithDefaults()}); err != nil {
		t.Fatalf("Reconcile (endpoint change): %v", err)
	}
}
