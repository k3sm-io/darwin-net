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
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// The routing table sits on every connection's accept path: proxy.handle calls
// PickSticky / PickStickyCluster per TCP accept and the UDP relay calls Pick per
// new flow. These benchmarks measure the pick under the shapes that matter:
//
//   - one hot key hammered from every core (a busy Service);
//   - many keys, one per goroutine (many Services: does one key's traffic stall
//     another's?);
//   - the sticky wrapper with affinity off (the actual TCP accept path) and with
//     ClientIP affinity on (a binding hit);
//   - picks while a reconcile rewrites the table underneath them.

// benchTable builds a table with n keys of k Ready backends each under aff.
func benchTable(n, k int, aff affinityConfig) (*RoutingTable, []PortKey) {
	tbl := NewRoutingTable(netip.MustParsePrefix("100.64.0.0/24"))
	keys := make([]PortKey, n)
	for i := range keys {
		keys[i] = PortKey{ClusterIP: fmt.Sprintf("10.43.%d.%d", i>>8, i&0xff), Port: 80, Protocol: netv1.ProtocolTCP}
		tbl.SetEndpointsPolicy(keys[i], benchEndpoints(i, k), trafficCluster, aff)
	}
	return tbl, keys
}

// benchEndpoints returns k Ready endpoints for key index i, half node-local.
func benchEndpoints(i, k int) []netv1.Endpoint {
	eps := make([]netv1.Endpoint, k)
	for j := range eps {
		ip := fmt.Sprintf("100.64.0.%d", (i*k+j)%250+1) // node-local
		if j%2 == 1 {
			ip = fmt.Sprintf("100.64.1.%d", (i*k+j)%250+1) // remote
		}
		eps[j] = netv1.Endpoint{IP: ip, Port: 8080, Ready: true}
	}
	return eps
}

// BenchmarkRoutingTablePick is one hot key picked from every core: the UDP
// relay's new-flow selector on a busy Service.
func BenchmarkRoutingTablePick(b *testing.B) {
	tbl, keys := benchTable(1, 8, affinityConfig{})
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := tbl.Pick(keys[0]); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkRoutingTablePickManyKeys gives each goroutine its own key, so any cost
// here beyond the single-key case is cross-Service serialization.
func BenchmarkRoutingTablePickManyKeys(b *testing.B) {
	const keys = 64
	tbl, ks := benchTable(keys, 8, affinityConfig{})
	var next atomic.Int64
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		key := ks[int(next.Add(1)-1)%keys]
		for pb.Next() {
			if _, err := tbl.Pick(key); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkRoutingTablePickSticky is the TCP accept path as proxy.handle drives it:
// PickSticky on a port with affinity off, so it must cost what Pick costs.
func BenchmarkRoutingTablePickSticky(b *testing.B) {
	tbl, keys := benchTable(1, 8, affinityConfig{})
	client := netip.MustParseAddr("100.64.0.200")
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		now := time.Now()
		for pb.Next() {
			if _, err := tbl.PickSticky(keys[0], client, now); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkRoutingTablePickStickyClientIP is a ClientIP-affinity binding hit: each
// goroutine is one client whose binding already exists and is refreshed per pick.
func BenchmarkRoutingTablePickStickyClientIP(b *testing.B) {
	tbl, keys := benchTable(1, 8, clientIPAffinity(time.Hour))
	var next atomic.Int64
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := int(next.Add(1)-1) % 250
		client := netip.AddrFrom4([4]byte{100, 64, 5, byte(i + 1)})
		now := time.Now()
		for pb.Next() {
			if _, err := tbl.PickSticky(keys[0], client, now); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkRoutingTablePickUnderReconcile measures picks on 64 keys while one
// goroutine reconciles a 65th key back to back. SYNTHETIC: a reconcile per
// microsecond is not a traffic shape; it isolates whether a writer stalls readers.
func BenchmarkRoutingTablePickUnderReconcile(b *testing.B) {
	const keys = 64
	tbl, ks := benchTable(keys+1, 8, affinityConfig{})
	churn := ks[keys]
	eps := benchEndpoints(keys, 8)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				tbl.SetEndpointsPolicy(churn, eps, trafficCluster, affinityConfig{})
			}
		}
	}()
	var next atomic.Int64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		key := ks[int(next.Add(1)-1)%keys]
		for pb.Next() {
			if _, err := tbl.Pick(key); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.StopTimer()
	close(stop)
	<-done
}
