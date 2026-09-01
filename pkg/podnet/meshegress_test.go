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
	"errors"
	"net/netip"
	"testing"
)

// TestMeshEgressSourceReserved is the M3.1 acceptance for the reserved mesh-egress
// source address: the /32 is derived from the node podCIDR (it is the .1 first
// host) AND it is excluded from the allocator — Allocate never hands it out, the
// first pod IP is .2, and AllocateSpecific of the reserved address is rejected.
// This is the load-bearing fix the re-plan calls out: the allocator used to hand
// out .1 as the first pod IP; reserving it gives the wireguard mesh a stable
// per-node egress source whose address is inside the node's own AllowedIPs.
func TestMeshEgressSourceReserved(t *testing.T) {
	t.Run("derived from node podCIDR (.1)", func(t *testing.T) {
		cases := []struct {
			cidr string
			want string
		}{
			{"100.64.0.0/24", "100.64.0.1"},
			{"100.64.7.0/24", "100.64.7.1"},
			{"100.127.255.0/24", "100.127.255.1"},
			{"10.0.5.0/24", "10.0.5.1"},
		}
		for _, tc := range cases {
			got, err := MeshEgressIP(netip.MustParsePrefix(tc.cidr))
			if err != nil {
				t.Fatalf("MeshEgressIP(%s): %v", tc.cidr, err)
			}
			if got.String() != tc.want {
				t.Fatalf("MeshEgressIP(%s) = %s, want %s", tc.cidr, got, tc.want)
			}
		}
	})

	t.Run("rejects a non-/24 or non-IPv4 CIDR", func(t *testing.T) {
		for _, bad := range []netip.Prefix{
			netip.MustParsePrefix("100.64.0.0/16"),
			netip.MustParsePrefix("100.64.0.0/25"),
			netip.MustParsePrefix("fd00::/24"),
			{},
		} {
			if _, err := MeshEgressIP(bad); !errors.Is(err, ErrOutOfRange) {
				t.Fatalf("MeshEgressIP(%s) err = %v, want ErrOutOfRange", bad, err)
			}
		}
	})

	t.Run("excluded from the allocator", func(t *testing.T) {
		cidr := netip.MustParsePrefix("100.64.0.0/24")
		a, err := NewAllocator(cidr)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}

		mesh, err := MeshEgressIP(cidr)
		if err != nil {
			t.Fatalf("MeshEgressIP: %v", err)
		}
		// The allocator's reserved address agrees with the canonical derivation.
		if a.MeshEgressIP() != mesh {
			t.Fatalf("allocator MeshEgressIP = %s, want %s", a.MeshEgressIP(), mesh)
		}
		if mesh.String() != "100.64.0.1" {
			t.Fatalf("mesh-egress = %s, want 100.64.0.1", mesh)
		}
		if got := a.Capacity(); got != 253 {
			t.Fatalf("Capacity = %d, want 253 (.0/.1/.255 reserved)", got)
		}

		// The first pod IP handed out is .2 — .0 (network) and .1 (mesh egress)
		// are reserved, so the allocator no longer hands out .1.
		first, err := a.Allocate()
		if err != nil {
			t.Fatalf("first Allocate: %v", err)
		}
		if first.String() != "100.64.0.2" {
			t.Fatalf("first Allocate = %s, want 100.64.0.2 (.1 reserved)", first)
		}

		// Draining the rest of the pool must never surface the mesh-egress address.
		for i := 0; i < 252; i++ {
			ip, err := a.Allocate()
			if err != nil {
				t.Fatalf("Allocate #%d: %v", i, err)
			}
			if ip == mesh {
				t.Fatalf("Allocate handed out the reserved mesh-egress address %s", ip)
			}
		}

		// AllocateSpecific of the reserved address is rejected (it is below the
		// usable host range), so a restart-reattach can never reclaim it for a pod.
		if _, err := a.AllocateSpecific(mesh); !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("AllocateSpecific(%s) err = %v, want ErrOutOfRange", mesh, err)
		}
	})
}

// TestMeshLinkAddressReserved is the acceptance for the mesh utun's own
// point-to-point address: it is derived from the node podCIDR (the .255 the
// allocator already reserves as the broadcast address), it is distinct from the
// mesh-egress source, and reusing the standing reservation costs no pod capacity —
// the pool is still the 253 addresses .2 through .254.
//
// The distinctness is the load-bearing half. macOS refuses an interface-bound
// route on an addressless utun, so the tunnel needs an address of its own; but an
// address that lives on the utun is reached OVER the utun, so it cannot be the
// mesh-egress source the node's own processes bind and dial.
func TestMeshLinkAddressReserved(t *testing.T) {
	t.Run("derived from node podCIDR (.255)", func(t *testing.T) {
		cases := []struct {
			cidr string
			want string
		}{
			{"100.64.0.0/24", "100.64.0.255"},
			{"100.64.7.0/24", "100.64.7.255"},
			{"100.127.255.0/24", "100.127.255.255"},
			{"10.0.5.0/24", "10.0.5.255"},
		}
		for _, tc := range cases {
			got, err := MeshLinkIP(netip.MustParsePrefix(tc.cidr))
			if err != nil {
				t.Fatalf("MeshLinkIP(%s): %v", tc.cidr, err)
			}
			if got.String() != tc.want {
				t.Fatalf("MeshLinkIP(%s) = %s, want %s", tc.cidr, got, tc.want)
			}
		}
	})

	t.Run("rejects a non-/24 or non-IPv4 CIDR", func(t *testing.T) {
		for _, bad := range []netip.Prefix{
			netip.MustParsePrefix("100.64.0.0/16"),
			netip.MustParsePrefix("100.64.0.0/25"),
			netip.MustParsePrefix("fd00::/24"),
			{},
		} {
			if _, err := MeshLinkIP(bad); !errors.Is(err, ErrOutOfRange) {
				t.Fatalf("MeshLinkIP(%s) err = %v, want ErrOutOfRange", bad, err)
			}
		}
	})

	t.Run("distinct from the mesh-egress source and never allocated", func(t *testing.T) {
		cidr := netip.MustParsePrefix("100.64.0.0/24")
		link, err := MeshLinkIP(cidr)
		if err != nil {
			t.Fatalf("MeshLinkIP: %v", err)
		}
		egress, err := MeshEgressIP(cidr)
		if err != nil {
			t.Fatalf("MeshEgressIP: %v", err)
		}
		if link == egress {
			t.Fatalf("mesh link address == mesh-egress source (%s): an address on the utun is reached over the utun, so a same-node dial of the mesh IP would be tunnelled and dropped", link)
		}

		a, err := NewAllocator(cidr)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		if got := a.Capacity(); got != 253 {
			t.Fatalf("Capacity = %d, want 253: the link address reuses the standing .255 reservation and must cost no pod capacity", got)
		}
		for i := 0; i < 253; i++ {
			ip, err := a.Allocate()
			if err != nil {
				t.Fatalf("Allocate #%d: %v", i, err)
			}
			if ip == link {
				t.Fatalf("Allocate handed out the mesh link address %s", ip)
			}
		}
		if _, err := a.AllocateSpecific(link); !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("AllocateSpecific(%s) err = %v, want ErrOutOfRange", link, err)
		}
	})
}
