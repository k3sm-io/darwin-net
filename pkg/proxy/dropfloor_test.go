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
	"log/slog"
	"net/netip"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// TestGenerationIgnoresOrderAndDuplicates pins that the backend-set generation
// moves only on a real change: the same endpoints in another order or with a
// duplicate keep it (so they cannot re-arm the drop Warn), a changed set or
// policy bumps it.
func TestGenerationIgnoresOrderAndDuplicates(t *testing.T) {
	t.Parallel()
	a := netv1.Endpoint{IP: "100.64.0.5", Port: 8080, Ready: true}
	b := netv1.Endpoint{IP: "100.64.1.6", Port: 8080, Ready: true}
	notReady := netv1.Endpoint{IP: "100.64.0.9", Port: 8080, Ready: false}
	key := PortKey{ClusterIP: "10.43.0.70", Port: 80, Protocol: netv1.ProtocolTCP}
	svc := serviceRef{Namespace: "default", Name: "web"}
	tbl := NewRoutingTable(netip.MustParsePrefix("100.64.0.0/24"))

	steps := []struct {
		name    string
		eps     []netv1.Endpoint
		policy  trafficPolicy
		wantGen uint64
	}{
		{"first install", []netv1.Endpoint{a, b}, trafficCluster, 1},
		{"reordered", []netv1.Endpoint{b, a}, trafficCluster, 1},
		{"duplicate address", []netv1.Endpoint{a, b, a}, trafficCluster, 1},
		{"an unready endpoint is not part of the set", []netv1.Endpoint{notReady, b, a}, trafficCluster, 1},
		{"shrunk", []netv1.Endpoint{a}, trafficCluster, 2},
		{"policy change", []netv1.Endpoint{a}, trafficLocal, 3},
		{"same again", []netv1.Endpoint{a, a}, trafficLocal, 3},
		{"drained", nil, trafficLocal, 4},
		{"still drained", nil, trafficLocal, 4},
	}
	for _, s := range steps {
		tbl.installEndpoints(key, svc, s.eps, s.policy, affinityConfig{})
		if g := tbl.VIPStates()[0].Generation; g != s.wantGen {
			t.Errorf("%s: generation = %d, want %d", s.name, g, s.wantGen)
		}
	}
}

// TestDropWarnFloor pins the per-key floor: whatever the generation does, one
// key warns at most once per dropWarnFloor, and a generation first dropped inside
// the floor still warns once the floor has passed.
func TestDropWarnFloor(t *testing.T) {
	t.Parallel()
	t0 := time.Unix(2_000_000, 0)
	m := &keyMeta{}
	claims := []struct {
		name string
		gen  uint64
		at   time.Duration
		want bool
	}{
		{"first drop warns", 1, 0, true},
		{"same generation stays quiet", 1, time.Second, false},
		{"new generation inside the floor stays quiet", 2, 2 * time.Second, false},
		{"that generation warns once the floor passed", 2, 11 * time.Second, true},
		{"churned generation inside the floor stays quiet", 3, 12 * time.Second, false},
		{"churned generation again inside the floor", 4, 15 * time.Second, false},
		{"the latest generation warns after the floor", 4, 22 * time.Second, true},
		{"an older generation never warns after a newer one", 3, 60 * time.Second, false},
	}
	for _, c := range claims {
		if got := m.claimDropWarn(c.gen, t0.Add(c.at)); got != c.want {
			t.Errorf("%s: claimDropWarn(%d, +%s) = %v, want %v", c.name, c.gen, c.at, got, c.want)
		}
	}

	t.Run("the floor survives generation churn through the table", func(t *testing.T) {
		tbl := NewRoutingTable(netip.MustParsePrefix("100.64.0.0/24"))
		key := PortKey{ClusterIP: "10.43.0.71", Port: 80, Protocol: netv1.ProtocolTCP}
		h := &captureHandler{}
		tbl.log = slog.New(h)
		remote := netv1.Endpoint{IP: "100.64.1.5", Port: 8080, Ready: true}
		for i := range 20 {
			// Alternate an empty set and a remote-only Local set: every install is a
			// new generation and every drop is a first drop of its generation.
			if i%2 == 0 {
				tbl.installEndpoints(key, serviceRef{"default", "web"}, nil, trafficLocal, affinityConfig{})
			} else {
				tbl.installEndpoints(key, serviceRef{"default", "web"}, []netv1.Endpoint{remote}, trafficLocal, affinityConfig{})
			}
			tbl.warnDrop(key, false, ErrNoBackends, t0.Add(time.Duration(i)*400*time.Millisecond))
		}
		if n := len(dropWarns(h)); n != 1 {
			t.Errorf("20 generations dropped within 8 s emitted %d Warns, want 1", n)
		}
	})
}
