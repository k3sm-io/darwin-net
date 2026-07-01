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

package proxy

import (
	"net"
	"net/netip"
	"testing"
)

// TestWithMeshEgressSourceBindsDialer proves the mesh-egress option wires the
// backend dialer's LocalAddr to the node's reserved mesh source (so cross-node
// dials egress the utun from an address inside this node's AllowedIPs and the
// wireguard return path is not blackholed), and that the zero address leaves the
// dialer on the kernel's default source selection (the single-node path).
func TestWithMeshEgressSourceBindsDialer(t *testing.T) {
	table := NewRoutingTable(netip.MustParsePrefix("100.64.0.0/24"))

	t.Run("valid source binds LocalAddr", func(t *testing.T) {
		src := netip.MustParseAddr("100.64.0.1")
		p := New(table, WithMeshEgressSource(src), withAliasManager(newNoopAliasManager()))
		la, ok := p.dialer.LocalAddr.(*net.TCPAddr)
		if !ok {
			t.Fatalf("dialer.LocalAddr = %#v, want *net.TCPAddr", p.dialer.LocalAddr)
		}
		if !la.IP.Equal(net.IP(src.AsSlice())) {
			t.Fatalf("dialer LocalAddr IP = %s, want %s", la.IP, src)
		}
		if la.Port != 0 {
			t.Fatalf("dialer LocalAddr port = %d, want 0 (ephemeral)", la.Port)
		}
		// The same source is retained for the UDP relay's per-flow upstream
		// source-bind (it cannot reuse the *net.TCPAddr dialer for "udp").
		if p.meshEgress != src {
			t.Fatalf("p.meshEgress = %s, want %s (retained for the UDP relay)", p.meshEgress, src)
		}
	})

	t.Run("zero source keeps default selection", func(t *testing.T) {
		p := New(table, WithMeshEgressSource(netip.Addr{}), withAliasManager(newNoopAliasManager()))
		if p.dialer.LocalAddr != nil {
			t.Fatalf("dialer.LocalAddr = %#v, want nil (no mesh source on a single node)", p.dialer.LocalAddr)
		}
		// The zero Addr stays invalid, so the UDP relay falls back to the kernel
		// default source on a single node.
		if p.meshEgress.IsValid() {
			t.Fatalf("p.meshEgress = %s, want invalid (single-node default source)", p.meshEgress)
		}
	})
}
