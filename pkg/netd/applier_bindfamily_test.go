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

package netd

import (
	"net/netip"
	"testing"
)

// TestBindFamily pins the family BindPort binds on: IPv4-only for an unmapped
// IPv4 address (the wildcard included), so an IPv4 holder of the port is
// detected, and the network unchanged for an IPv6 address. The real-socket half
// is TestBindPortIPv4WildcardDetectsAnIPv4Holder (integration).
func TestBindFamily(t *testing.T) {
	cases := []struct {
		network, addr, want string
	}{
		{"tcp", "0.0.0.0", "tcp4"},
		{"udp", "0.0.0.0", "udp4"},
		{"tcp", "10.43.0.10", "tcp4"},
		{"udp", "10.43.0.10", "udp4"},
		{"tcp", "127.0.0.1", "tcp4"},
		{"tcp", "::", "tcp"},
		{"udp", "::", "udp"},
		{"tcp", "::1", "tcp"},
		{"udp", "fd00::10", "udp"},
		{"tcp", "::ffff:10.43.0.10", "tcp4"},
	}
	for _, tc := range cases {
		t.Run(tc.network+" "+tc.addr, func(t *testing.T) {
			if got := bindFamily(tc.network, netip.MustParseAddr(tc.addr)); got != tc.want {
				t.Fatalf("bindFamily(%s, %s) = %q, want %q", tc.network, tc.addr, got, tc.want)
			}
		})
	}
}
