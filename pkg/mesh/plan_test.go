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
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
)

// wgKeyB64 builds a deterministic, valid 32-byte wireguard key base64-encoded, so
// table tests can vary the key per peer without a real keygen.
func wgKeyB64(seed byte) string {
	var k [wgKeyBytes]byte
	k[0] = seed
	k[31] = seed
	return base64.StdEncoding.EncodeToString(k[:])
}

// peerSpec builds a defaulted MeshPeerSpec whose AllowedIPs equals its podCIDR
// (the valid single-source-of-truth shape).
func peerSpec(node, podCIDR, endpoint string, seed byte) netv1.MeshPeerSpec {
	return netv1.MeshPeerSpec{
		NodeName:   node,
		PublicKey:  wgKeyB64(seed),
		Endpoint:   endpoint,
		PodCIDR:    podCIDR,
		AllowedIPs: []string{podCIDR},
	}.WithDefaults()
}

func containsPrefix(set []netip.Prefix, want string) bool {
	w := netip.MustParsePrefix(want)
	for _, p := range set {
		if p == w {
			return true
		}
	}
	return false
}

// TestMeshRoutesPerPeerNotAggregate is the M3.1 acceptance for the per-peer kernel
// routes: the route set is exactly one route per peer podCIDR, and this node's own
// /24 and the 100.64.0.0/10 cluster aggregate are NEVER in it (routing either to
// the utun would steal same-node lo0 loopback traffic — wireguard-go installs no
// kernel routes itself, so this set is the sole route authority).
func TestMeshRoutesPerPeerNotAggregate(t *testing.T) {
	self := netip.MustParsePrefix("100.64.0.0/24")
	peers := []netv1.MeshPeerSpec{
		{PodCIDR: "100.64.2.0/24"}, // valid peer
		{PodCIDR: "100.64.1.0/24"}, // valid peer (out of order — result must sort)
		{PodCIDR: "100.64.0.0/24"}, // == self: must be excluded (loopback theft)
		{PodCIDR: "100.64.0.0/10"}, // the cluster aggregate: must be excluded
		{PodCIDR: "100.64.0.0/16"}, // a supernet of self: must be excluded
		{PodCIDR: "100.64.1.0/24"}, // duplicate of a valid peer: must be deduped
		{PodCIDR: "not-a-cidr"},    // malformed: skipped
		{PodCIDR: ""},              // empty: skipped
	}

	routes, err := RouteSet(self, peers)
	if err != nil {
		t.Fatalf("RouteSet: %v", err)
	}

	if len(routes) != 2 {
		t.Fatalf("RouteSet = %v, want exactly 2 peer /24s", routes)
	}
	if !containsPrefix(routes, "100.64.1.0/24") || !containsPrefix(routes, "100.64.2.0/24") {
		t.Fatalf("RouteSet = %v, want the two valid peer /24s", routes)
	}
	// The load-bearing exclusions: never the node's own /24 nor the aggregate.
	if containsPrefix(routes, "100.64.0.0/24") {
		t.Fatalf("RouteSet steers this node's own /24 to the utun: %v", routes)
	}
	if containsPrefix(routes, "100.64.0.0/10") {
		t.Fatalf("RouteSet steers the 100.64.0.0/10 aggregate to the utun: %v", routes)
	}
	if containsPrefix(routes, "100.64.0.0/16") {
		t.Fatalf("RouteSet steers a supernet of this node to the utun: %v", routes)
	}
	// Deterministically sorted.
	if routes[0].Addr().Compare(routes[1].Addr()) >= 0 {
		t.Fatalf("RouteSet not sorted ascending: %v", routes)
	}

	if _, err := RouteSet(netip.MustParsePrefix("100.64.0.0/16"), peers); !errors.Is(err, ErrSelfCIDR) {
		t.Fatalf("RouteSet with non-/24 self err = %v, want ErrSelfCIDR", err)
	}
}

// TestMeshAllowedIPsEqualsCIDR is the M3.1 acceptance for the node /24 single
// source of truth: per peer, AllowedIPs must EQUAL the podCIDR — equality, not
// merely symmetry, because a symmetric-but-wrong AllowedIPs still blackholes.
func TestMeshAllowedIPsEqualsCIDR(t *testing.T) {
	cases := []struct {
		name    string
		spec    netv1.MeshPeerSpec
		wantErr bool
	}{
		{
			name: "exact match",
			spec: netv1.MeshPeerSpec{NodeName: "a", PodCIDR: "100.64.1.0/24", AllowedIPs: []string{"100.64.1.0/24"}},
		},
		{
			name: "unmasked host bits still equal once masked",
			spec: netv1.MeshPeerSpec{NodeName: "a", PodCIDR: "100.64.1.0/24", AllowedIPs: []string{"100.64.1.7/24"}},
		},
		{
			name:    "symmetric but wrong /24 blackholes",
			spec:    netv1.MeshPeerSpec{NodeName: "a", PodCIDR: "100.64.1.0/24", AllowedIPs: []string{"100.64.9.0/24"}},
			wantErr: true,
		},
		{
			name:    "aggregate is not the podCIDR",
			spec:    netv1.MeshPeerSpec{NodeName: "a", PodCIDR: "100.64.1.0/24", AllowedIPs: []string{"100.64.0.0/10"}},
			wantErr: true,
		},
		{
			name:    "extra entry beyond the podCIDR",
			spec:    netv1.MeshPeerSpec{NodeName: "a", PodCIDR: "100.64.1.0/24", AllowedIPs: []string{"100.64.1.0/24", "100.64.2.0/24"}},
			wantErr: true,
		},
		{
			name:    "empty allowedIPs",
			spec:    netv1.MeshPeerSpec{NodeName: "a", PodCIDR: "100.64.1.0/24"},
			wantErr: true,
		},
		{
			name:    "malformed allowedIP",
			spec:    netv1.MeshPeerSpec{NodeName: "a", PodCIDR: "100.64.1.0/24", AllowedIPs: []string{"garbage"}},
			wantErr: true,
		},
		{
			name:    "malformed podCIDR",
			spec:    netv1.MeshPeerSpec{NodeName: "a", PodCIDR: "nope", AllowedIPs: []string{"100.64.1.0/24"}},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := AllowedIPsMatchCIDR(tc.spec)
			if tc.wantErr {
				if !errors.Is(err, ErrPeerConfig) {
					t.Fatalf("AllowedIPsMatchCIDR err = %v, want ErrPeerConfig", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("AllowedIPsMatchCIDR unexpected err: %v", err)
			}
		})
	}
}

// TestMeshConstantsAndMSSClamp pins the link constants and the MSS-clamp
// derivation: the clamp must be the mesh MTU minus the IPv4+TCP headers, the value
// a pf scrub uses so a pod socket on the lo0 MTU (16384) cannot advertise an MSS
// too large for the 1380 utun (a large-payload cross-node TCP blackhole).
func TestMeshConstantsAndMSSClamp(t *testing.T) {
	if MTU != 1380 {
		t.Fatalf("MTU = %d, want 1380", MTU)
	}
	if PersistentKeepaliveSeconds != 25 {
		t.Fatalf("PersistentKeepaliveSeconds = %d, want 25", PersistentKeepaliveSeconds)
	}
	if got := MaxMSS(1380); got != 1340 {
		t.Fatalf("MaxMSS(1380) = %d, want 1340", got)
	}
	if got := MaxMSS(1500); got != 1460 {
		t.Fatalf("MaxMSS(1500) = %d, want 1460", got)
	}
	if MSSClamp != 1340 {
		t.Fatalf("MSSClamp = %d, want 1340 (MTU-40)", MSSClamp)
	}
}

// TestMeshPFClampScopedToUTUN proves the pf scrub rule is scoped to the utun
// egress and clamps the MSS, and is NOT applied to lo0 (clamping loopback would
// needlessly shrink same-node segments).
func TestMeshPFClampScopedToUTUN(t *testing.T) {
	rule := PFMSSClampRule("utun4", MSSClamp)
	for _, want := range []string{"scrub out", "on utun4", "proto tcp", "max-mss 1340"} {
		if !strings.Contains(rule, want) {
			t.Fatalf("pf rule %q missing %q", rule, want)
		}
	}
	if strings.Contains(rule, "lo0") {
		t.Fatalf("pf rule clamps lo0 (must be utun-only): %q", rule)
	}
}

// TestMeshPlanUAPIAndKeyHex covers the wireguard UAPI generation and the
// base64->hex public-key encoding the UAPI requires.
func TestMeshPlanUAPIAndKeyHex(t *testing.T) {
	t.Run("wgKeyHex", func(t *testing.T) {
		hexKey, err := wgKeyHex(wgKeyB64(0x01))
		if err != nil {
			t.Fatalf("wgKeyHex: %v", err)
		}
		if len(hexKey) != 2*wgKeyBytes {
			t.Fatalf("hex key len = %d, want %d", len(hexKey), 2*wgKeyBytes)
		}
		if _, err := wgKeyHex("!!not base64!!"); err == nil {
			t.Fatal("wgKeyHex accepted invalid base64")
		}
		if _, err := wgKeyHex(base64.StdEncoding.EncodeToString(make([]byte, 16))); err == nil {
			t.Fatal("wgKeyHex accepted a 16-byte key")
		}
	})

	t.Run("UAPI full resync", func(t *testing.T) {
		self := netip.MustParsePrefix("100.64.0.0/24")
		plan, err := BuildPlan(self, []netv1.MeshPeerSpec{
			peerSpec("nodeB", "100.64.1.0/24", "192.0.2.10:51820", 0x42),
		})
		if err != nil {
			t.Fatalf("BuildPlan: %v", err)
		}
		uapi := plan.UAPI()
		for _, want := range []string{
			"replace_peers=true\n",
			"endpoint=192.0.2.10:51820\n",
			"persistent_keepalive_interval=25\n",
			"replace_allowed_ips=true\n",
			"allowed_ip=100.64.1.0/24\n",
		} {
			if !strings.Contains(uapi, want) {
				t.Fatalf("UAPI missing %q in:\n%s", want, uapi)
			}
		}
		keyHex, _ := wgKeyHex(wgKeyB64(0x42))
		if !strings.Contains(uapi, "public_key="+keyHex+"\n") {
			t.Fatalf("UAPI missing hex public_key %q in:\n%s", keyHex, uapi)
		}
	})
}

// TestBuildPlanSkipsSelfAndInvalid proves BuildPlan drops the node's own MeshPeer
// silently (never a route), records invalid peers in Skipped (for logging) without
// failing the whole plan, and gates on the schema version.
func TestBuildPlanSkipsSelfAndInvalid(t *testing.T) {
	self := netip.MustParsePrefix("100.64.0.0/24")

	selfPeer := peerSpec("self", "100.64.0.0/24", "192.0.2.1:51820", 0x01)
	good := peerSpec("nodeB", "100.64.1.0/24", "192.0.2.2:51820", 0x02)
	wrongAllowed := peerSpec("nodeC", "100.64.2.0/24", "192.0.2.3:51820", 0x03)
	wrongAllowed.AllowedIPs = []string{"100.64.99.0/24"} // symmetric-but-wrong
	badVersion := peerSpec("nodeD", "100.64.3.0/24", "192.0.2.4:51820", 0x04)
	badVersion.SchemaVersion = 99 // unsupported (WithDefaults leaves a non-zero value)

	plan, err := BuildPlan(self, []netv1.MeshPeerSpec{selfPeer, good, wrongAllowed, badVersion})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	if len(plan.Peers) != 1 || plan.Peers[0].NodeName != "nodeB" {
		t.Fatalf("plan.Peers = %+v, want only nodeB", plan.Peers)
	}
	if len(plan.Routes) != 1 || plan.Routes[0].String() != "100.64.1.0/24" {
		t.Fatalf("plan.Routes = %v, want [100.64.1.0/24]", plan.Routes)
	}
	// self is silently omitted (not a skip), wrongAllowed and badVersion are skips.
	skipped := map[string]bool{}
	for _, s := range plan.Skipped {
		skipped[s.NodeName] = true
	}
	if skipped["self"] {
		t.Fatalf("the node's own peer must be omitted silently, not recorded as skipped: %+v", plan.Skipped)
	}
	if !skipped["nodeC"] || !skipped["nodeD"] {
		t.Fatalf("Skipped = %+v, want nodeC (wrong allowedIPs) and nodeD (bad version)", plan.Skipped)
	}
}
