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

package ingress

import (
	"net/netip"
	"testing"
)

// be builds a distinguishable Backend for the precedence matrix.
func be(port uint16) Backend {
	return Backend{VIP: netip.MustParseAddr("10.43.0.10"), Port: port}
}

// TestIngressRouteTablePrecedence is the M10.3 routing-core gate: the pathType
// precedence matrix (Exact vs Prefix, longest match, segment boundaries), the
// host-specific-over-hostless tiering, the default backend, and the
// router-level 404 (ok=false).
func TestIngressRouteTablePrecedence(t *testing.T) {
	rules := []Rule{
		{Host: "App.Example.Com", Path: "/", PathType: PathTypePrefix, Backend: be(1)},
		{Host: "app.example.com", Path: "/api", PathType: PathTypePrefix, Backend: be(2)},
		{Host: "app.example.com", Path: "/api/v2", PathType: PathTypePrefix, Backend: be(3)},
		{Host: "app.example.com", Path: "/api", PathType: PathTypeExact, Backend: be(4)},
		{Host: "", Path: "/api", PathType: PathTypePrefix, Backend: be(5)},
		{Host: "", Path: "/fallback", PathType: PathTypePrefix, Backend: be(6)},
	}
	def := be(9)

	withDefault := NewRouteTable()
	withDefault.Update(rules, &def)
	noDefault := NewRouteTable()
	noDefault.Update(rules, nil)

	tests := []struct {
		name   string
		table  *RouteTable
		host   string
		path   string
		want   Backend
		wantOK bool
	}{
		{"exact beats prefix at equal path", withDefault, "app.example.com", "/api", be(4), true},
		{"prefix matches sub-path", withDefault, "app.example.com", "/api/users", be(2), true},
		{"longest prefix wins", withDefault, "app.example.com", "/api/v2/items", be(3), true},
		{"exact does not match sub-path (prefix does)", withDefault, "app.example.com", "/api/", be(2), true},
		{"segment boundary: /apix is not under /api", withDefault, "app.example.com", "/apix", be(1), true},
		{"root prefix catches everything on its host", withDefault, "app.example.com", "/anything/else", be(1), true},
		{"rule host is normalized to lowercase on Update", withDefault, "app.example.com", "/", be(1), true},
		{"host-specific tier beats hostless at same path", withDefault, "app.example.com", "/api/x", be(2), true},
		{"hostless tier serves an unknown host", withDefault, "other.example.com", "/api/x", be(5), true},
		{"hostless prefix on unknown host", withDefault, "other.example.com", "/fallback/y", be(6), true},
		{"no rule match falls to the default backend", withDefault, "other.example.com", "/nope", be(9), true},
		{"no rule match and no default is the router 404", noDefault, "other.example.com", "/nope", Backend{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.table.Match(tt.host, tt.path)
			if ok != tt.wantOK || (ok && got != tt.want) {
				t.Fatalf("Match(%q, %q) = (%v, %v), want (%v, %v)", tt.host, tt.path, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// TestIngressRouteTableEmptyAndSwap covers the zero table and the atomic
// snapshot swap: an empty table 404s, and an Update replaces the whole rule
// set (old rules do not linger).
func TestIngressRouteTableEmptyAndSwap(t *testing.T) {
	tb := NewRouteTable()
	if _, ok := tb.Match("a.example.com", "/"); ok {
		t.Fatal("empty table matched")
	}
	tb.Update([]Rule{{Host: "a.example.com", Path: "/", PathType: PathTypePrefix, Backend: be(1)}}, nil)
	if got, ok := tb.Match("a.example.com", "/x"); !ok || got != be(1) {
		t.Fatalf("after first update: got (%v, %v)", got, ok)
	}
	tb.Update([]Rule{{Host: "b.example.com", Path: "/", PathType: PathTypePrefix, Backend: be(2)}}, nil)
	if _, ok := tb.Match("a.example.com", "/x"); ok {
		t.Fatal("stale rule survived the snapshot swap")
	}
	if got, ok := tb.Match("b.example.com", "/x"); !ok || got != be(2) {
		t.Fatalf("after second update: got (%v, %v)", got, ok)
	}
}
