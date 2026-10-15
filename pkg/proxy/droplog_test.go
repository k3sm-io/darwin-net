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
	"net"
	"net/netip"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// dropWarns returns the captured dropped-connection Warns.
func dropWarns(h *captureHandler) []slog.Record {
	var out []slog.Record
	for _, r := range h.warns() {
		if r.Message == "service port is dropping connections: no backend to route to" {
			out = append(out, r)
		}
	}
	return out
}

// dropOne drives one accepted connection through handle over a net.Pipe: no
// socket, no listener, no Run. The pick fails before any dial, so handle returns
// after logging.
func dropOne(t *testing.T, p *Proxy, key PortKey) {
	t.Helper()
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	p.handle(client, key, false)
}

// TestNoBackendDropWarnsOncePerKey pins the dropped-connection signal: a VIP that
// drops connections (no Ready backend, or no node-local one under
// internalTrafficPolicy:Local) logs one Warn per backend set, naming the VIP, the
// Service, the policy and the backend counts; repeated drops on the same set stay
// quiet, re-installing the identical set does not re-arm it, and a different set
// does. Before this signal existed both drops were Debug only, so every Warn
// count asserted here was zero.
func TestNoBackendDropWarnsOncePerKey(t *testing.T) {
	t.Parallel()
	key := PortKey{ClusterIP: "10.43.0.60", Port: 80, Protocol: netv1.ProtocolTCP}
	svc := serviceRef{Namespace: "default", Name: "web"}
	remote := []netv1.Endpoint{{IP: "100.64.1.5", Port: 8080, Ready: true}}
	twoRemote := append([]netv1.Endpoint{{IP: "100.64.1.6", Port: 8080, Ready: true}}, remote...)

	h := &captureHandler{}
	tbl := NewRoutingTable(netip.MustParsePrefix("100.64.0.0/24"))
	p := New(tbl, WithLogger(slog.New(h)))
	// Each step runs past the per-key Warn floor, so only the generation decides.
	clock := time.Unix(1_000_000, 0)
	p.now = func() time.Time { return clock }

	type want struct {
		warns    int
		policy   string
		backends string
		local    string
		reason   string
	}
	steps := []struct {
		name    string
		install func()
		drops   int
		want    want
	}{
		{
			name:    "empty set warns once over two drops",
			install: func() { tbl.installEndpoints(key, svc, nil, trafficCluster, affinityConfig{}) },
			drops:   2,
			want:    want{1, "Cluster", "0", "0", ErrNoBackends.Error()},
		},
		{
			name:    "identical empty set does not re-arm",
			install: func() { tbl.installEndpoints(key, svc, nil, trafficCluster, affinityConfig{}) },
			drops:   2,
			want:    want{1, "Cluster", "0", "0", ErrNoBackends.Error()},
		},
		{
			name:    "a different set re-arms: Local with only remote backends",
			install: func() { tbl.installEndpoints(key, svc, remote, trafficLocal, affinityConfig{}) },
			drops:   3,
			want:    want{2, "Local", "1", "0", ErrNoLocalBackends.Error()},
		},
		{
			name:    "identical non-empty set does not re-arm",
			install: func() { tbl.installEndpoints(key, svc, remote, trafficLocal, affinityConfig{}) },
			drops:   2,
			want:    want{2, "Local", "1", "0", ErrNoLocalBackends.Error()},
		},
		{
			name:    "a grown set re-arms",
			install: func() { tbl.installEndpoints(key, svc, twoRemote, trafficLocal, affinityConfig{}) },
			drops:   2,
			want:    want{3, "Local", "2", "0", ErrNoLocalBackends.Error()},
		},
	}
	for _, s := range steps {
		clock = clock.Add(dropWarnFloor + time.Second)
		s.install()
		for range s.drops {
			dropOne(t, p, key)
		}
		got := dropWarns(h)
		if len(got) != s.want.warns {
			t.Fatalf("%s: %d drop Warns, want %d", s.name, len(got), s.want.warns)
		}
		last := got[len(got)-1]
		for attrKey, wantVal := range map[string]string{
			"vip":           key.String(),
			"service":       "default/web",
			"policy":        s.want.policy,
			"backends":      s.want.backends,
			"localBackends": s.want.local,
			"reason":        s.want.reason,
		} {
			if v, ok := attr(last, attrKey); !ok || v != wantVal {
				t.Errorf("%s: Warn %s = %q (present %v), want %q", s.name, attrKey, v, ok, wantVal)
			}
		}
	}

	t.Run("a deleted key is not warned about", func(t *testing.T) {
		clock = clock.Add(dropWarnFloor + time.Second)
		before := len(dropWarns(h))
		tbl.Delete(key)
		dropOne(t, p, key)
		if n := len(dropWarns(h)); n != before {
			t.Errorf("drop on a deleted key emitted %d Warns, want 0", n-before)
		}
	})
}
