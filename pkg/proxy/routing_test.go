package proxy

import (
	"errors"
	"net/netip"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
)

// keyFor builds a TCP PortKey for the common test VIP.
func keyFor(clusterIP string, port int32) PortKey {
	return PortKey{ClusterIP: clusterIP, Port: port, Protocol: netv1.ProtocolTCP}
}

// TestRoutingTableReadyFilter maps to acceptance M1.1-a1 (pure routing table):
// an unready endpoint is NEVER admitted to the table and therefore can never be
// picked. This is the load-balancing safety invariant.
func TestRoutingTableReadyFilter(t *testing.T) {
	t.Parallel()
	key := keyFor("10.43.0.10", 80)

	cases := []struct {
		name      string
		eps       []netv1.Endpoint
		wantReady []string // IPs expected in the table, in sorted order
		wantNever []string // IPs that must NEVER be returned by any pick
	}{
		{
			name: "drops the single unready endpoint",
			eps: []netv1.Endpoint{
				{IP: "10.42.0.1", Port: 8080, Ready: true},
				{IP: "10.42.0.2", Port: 8080, Ready: false},
				{IP: "10.42.0.3", Port: 8080, Ready: true},
			},
			wantReady: []string{"10.42.0.1", "10.42.0.3"},
			wantNever: []string{"10.42.0.2"},
		},
		{
			name: "all unready yields empty table",
			eps: []netv1.Endpoint{
				{IP: "10.42.0.1", Port: 8080, Ready: false},
				{IP: "10.42.0.2", Port: 8080, Ready: false},
			},
			wantReady: nil,
			wantNever: []string{"10.42.0.1", "10.42.0.2"},
		},
		{
			name: "skips invalid endpoints (empty IP, bad port) even if ready",
			eps: []netv1.Endpoint{
				{IP: "10.42.0.1", Port: 8080, Ready: true},
				{IP: "", Port: 8080, Ready: true},
				{IP: "10.42.0.9", Port: 0, Ready: true},
				{IP: "not-an-ip", Port: 8080, Ready: true},
			},
			wantReady: []string{"10.42.0.1"},
			wantNever: []string{"", "10.42.0.9", "not-an-ip"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tbl := NewRoutingTable(netip.Prefix{})
			n := tbl.SetEndpoints(key, tc.eps)
			if n != len(tc.wantReady) {
				t.Fatalf("SetEndpoints returned %d ready, want %d", n, len(tc.wantReady))
			}

			gotIPs := backendIPs(tbl.Backends(key))
			if !equalStrings(gotIPs, tc.wantReady) {
				t.Fatalf("table backends = %v, want %v", gotIPs, tc.wantReady)
			}

			// Exhaustively pick far more than there are backends; assert no
			// never-IP ever appears and every pick is a ready IP.
			seen := map[string]bool{}
			for i := 0; i < 1000; i++ {
				be, err := tbl.Pick(key)
				if len(tc.wantReady) == 0 {
					if !errors.Is(err, ErrNoBackends) {
						t.Fatalf("Pick on empty table = %v, want ErrNoBackends", err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("Pick: %v", err)
				}
				ip := be.Addr().Addr().String()
				seen[ip] = true
				if contains(tc.wantNever, ip) {
					t.Fatalf("Pick returned NEVER-eligible (unready/invalid) backend %q", ip)
				}
			}
			// Every ready backend should have been selected by round-robin.
			for _, ip := range tc.wantReady {
				if !seen[ip] {
					t.Fatalf("ready backend %q was never selected", ip)
				}
			}
		})
	}
}

// TestRoutingTablePickDistribution maps to acceptance M1.1-a1 (load-balances
// across endpoints): round-robin Pick fans out evenly and the explicit-index
// PickAt is deterministic, so the distribution is table-assertable.
func TestRoutingTablePickDistribution(t *testing.T) {
	t.Parallel()
	key := keyFor("10.43.0.10", 80)
	tbl := NewRoutingTable(netip.Prefix{})
	tbl.SetEndpoints(key, []netv1.Endpoint{
		{IP: "10.42.0.1", Port: 8080, Ready: true},
		{IP: "10.42.0.2", Port: 8080, Ready: true},
		{IP: "10.42.0.3", Port: 8080, Ready: true},
		{IP: "10.42.0.4", Port: 8080, Ready: true},
	})
	// Sorted order is deterministic: .1 .2 .3 .4.
	want := []string{"10.42.0.1", "10.42.0.2", "10.42.0.3", "10.42.0.4"}

	t.Run("round-robin cycles in sorted order", func(t *testing.T) {
		t.Parallel()
		// Fresh table so the cursor starts at 0 independent of the parent.
		rt := NewRoutingTable(netip.Prefix{})
		rt.SetEndpoints(key, []netv1.Endpoint{
			{IP: "10.42.0.1", Port: 8080, Ready: true},
			{IP: "10.42.0.2", Port: 8080, Ready: true},
			{IP: "10.42.0.3", Port: 8080, Ready: true},
			{IP: "10.42.0.4", Port: 8080, Ready: true},
		})
		for round := 0; round < 3; round++ {
			for i, wantIP := range want {
				be, err := rt.Pick(key)
				if err != nil {
					t.Fatalf("Pick: %v", err)
				}
				if got := be.Addr().Addr().String(); got != wantIP {
					t.Fatalf("round %d pick %d = %s, want %s", round, i, got, wantIP)
				}
			}
		}
	})

	t.Run("even distribution over a full multiple of N", func(t *testing.T) {
		t.Parallel()
		rt := NewRoutingTable(netip.Prefix{})
		rt.SetEndpoints(key, []netv1.Endpoint{
			{IP: "10.42.0.1", Port: 8080, Ready: true},
			{IP: "10.42.0.2", Port: 8080, Ready: true},
			{IP: "10.42.0.3", Port: 8080, Ready: true},
			{IP: "10.42.0.4", Port: 8080, Ready: true},
		})
		counts := map[string]int{}
		const rounds = 250
		for i := 0; i < rounds*len(want); i++ {
			be, err := rt.Pick(key)
			if err != nil {
				t.Fatalf("Pick: %v", err)
			}
			counts[be.Addr().Addr().String()]++
		}
		for _, ip := range want {
			if counts[ip] != rounds {
				t.Fatalf("backend %s selected %d times, want exactly %d", ip, counts[ip], rounds)
			}
		}
	})

	t.Run("PickAt is deterministic by explicit index", func(t *testing.T) {
		t.Parallel()
		for i, wantIP := range want {
			be, err := tbl.PickAt(key, uint64(i))
			if err != nil {
				t.Fatalf("PickAt(%d): %v", i, err)
			}
			if got := be.Addr().Addr().String(); got != wantIP {
				t.Fatalf("PickAt(%d) = %s, want %s", i, got, wantIP)
			}
		}
		// Index wraps modulo N.
		be, err := tbl.PickAt(key, uint64(len(want)))
		if err != nil {
			t.Fatalf("PickAt wrap: %v", err)
		}
		if got := be.Addr().Addr().String(); got != want[0] {
			t.Fatalf("PickAt(N) = %s, want wrap to %s", got, want[0])
		}
	})
}

// TestRoutingTableChurn asserts the cursor resets and stale backends disappear
// when the Ready set changes, so a removed backend is never picked afterwards.
func TestRoutingTableChurn(t *testing.T) {
	t.Parallel()
	key := keyFor("10.43.0.10", 80)
	tbl := NewRoutingTable(netip.Prefix{})

	tbl.SetEndpoints(key, []netv1.Endpoint{
		{IP: "10.42.0.1", Port: 8080, Ready: true},
		{IP: "10.42.0.2", Port: 8080, Ready: true},
	})
	if _, err := tbl.Pick(key); err != nil {
		t.Fatalf("Pick: %v", err)
	}

	// Endpoint .2 goes away; .3 appears.
	tbl.SetEndpoints(key, []netv1.Endpoint{
		{IP: "10.42.0.1", Port: 8080, Ready: true},
		{IP: "10.42.0.3", Port: 8080, Ready: true},
	})
	for i := 0; i < 100; i++ {
		be, err := tbl.Pick(key)
		if err != nil {
			t.Fatalf("Pick: %v", err)
		}
		if ip := be.Addr().Addr().String(); ip == "10.42.0.2" {
			t.Fatalf("removed backend 10.42.0.2 was picked after churn")
		}
	}

	// Delete clears it entirely.
	tbl.Delete(key)
	if _, err := tbl.Pick(key); !errors.Is(err, ErrNoBackends) {
		t.Fatalf("Pick after Delete = %v, want ErrNoBackends", err)
	}
}

// TestRoutingTableLocality asserts backend locality is computed from the node
// podCIDR with a cheap Contains: in-CIDR is local, out-of-CIDR is remote, and a
// zero podCIDR yields unknown.
func TestRoutingTableLocality(t *testing.T) {
	t.Parallel()
	key := keyFor("10.43.0.10", 80)

	t.Run("classifies local vs remote against podCIDR", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.MustParsePrefix("100.64.0.0/24"))
		tbl.SetEndpoints(key, []netv1.Endpoint{
			{IP: "100.64.0.5", Port: 8080, Ready: true}, // in CIDR -> local
			{IP: "100.64.1.5", Port: 8080, Ready: true}, // out of /24 -> remote
		})
		got := map[string]Locality{}
		for _, be := range tbl.Backends(key) {
			got[be.Addr().Addr().String()] = be.Locality()
		}
		if got["100.64.0.5"] != LocalityLocal {
			t.Fatalf("100.64.0.5 locality = %v, want local", got["100.64.0.5"])
		}
		if got["100.64.1.5"] != LocalityRemote {
			t.Fatalf("100.64.1.5 locality = %v, want remote", got["100.64.1.5"])
		}
	})

	t.Run("zero podCIDR yields unknown", func(t *testing.T) {
		t.Parallel()
		tbl := NewRoutingTable(netip.Prefix{})
		tbl.SetEndpoints(key, []netv1.Endpoint{{IP: "100.64.0.5", Port: 8080, Ready: true}})
		bes := tbl.Backends(key)
		if len(bes) != 1 || bes[0].Locality() != LocalityUnknown {
			t.Fatalf("locality = %v, want unknown", bes)
		}
	})
}

func backendIPs(bes []backend) []string {
	out := make([]string, len(bes))
	for i, b := range bes {
		out[i] = b.Addr().Addr().String()
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
