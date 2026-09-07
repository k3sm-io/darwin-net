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
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// TestRoutingTableConcurrentPicksAndWriters hammers the table from every side at
// once — Pick, PickSticky with affinity off and on, PickStickyCluster, a writer
// toggling one port's affinity mode, a writer deleting and restoring another, a
// transport-override writer, and the sweeper — and asserts, under -race, the two
// things the lock split must keep true:
//
//  1. Every pick returns a member of that key's Ready set (or ErrNoBackends while
//     the deleted key is absent): a reader never sees a torn generation.
//  2. Once the writers stop, affinityCount equals the summed cardinality of the
//     affinity map, and no port whose final state is affinity-off or absent holds a
//     binding: the store-then-purge order plus the pick's re-validation closes the
//     window in which a pick could resurrect a purged binding.
func TestRoutingTableConcurrentPicksAndWriters(t *testing.T) {
	t.Parallel()
	tbl := NewRoutingTable(netip.MustParsePrefix("100.64.0.0/24"))
	mk := func(ip string) PortKey { return PortKey{ClusterIP: ip, Port: 80, Protocol: netv1.ProtocolTCP} }
	toggled, churned, sticky, plain := mk("10.43.0.1"), mk("10.43.0.2"), mk("10.43.0.3"), mk("10.43.0.4")
	eps := func(base int) []netv1.Endpoint {
		out := make([]netv1.Endpoint, 4)
		for i := range out {
			out[i] = netv1.Endpoint{IP: netip.AddrFrom4([4]byte{100, 64, 0, byte(base + i)}).String(), Port: 8080, Ready: true}
		}
		return out
	}
	allowed := map[PortKey]map[string]bool{}
	for key, base := range map[PortKey]int{toggled: 10, churned: 20, sticky: 30, plain: 40} {
		e := eps(base)
		allowed[key] = endpointIPSet(e)
		aff := affinityConfig{}
		if key == sticky || key == toggled {
			aff = clientIPAffinity(time.Hour)
		}
		tbl.SetEndpointsPolicy(key, e, trafficCluster, aff)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	fail := make(chan string, 64)
	report := func(msg string) {
		select {
		case fail <- msg:
		default:
		}
	}
	check := func(key PortKey, be backend, err error) {
		if err != nil {
			if key == churned && errors.Is(err, ErrNoBackends) {
				return
			}
			report(key.String() + ": " + err.Error())
			return
		}
		if !allowed[key][be.Addr().Addr().String()] {
			report(key.String() + ": picked " + be.Addr().String() + " outside the Ready set")
		}
	}
	spawn := func(n int, f func(i int)) {
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
						f(i)
					}
				}
			}(i)
		}
	}
	clientOf := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{100, 64, 9, byte(i + 1)}) }

	// Readers.
	spawn(4, func(i int) { be, err := tbl.Pick(plain); check(plain, be, err) })
	spawn(4, func(i int) { be, err := tbl.PickSticky(sticky, clientOf(i), time.Now()); check(sticky, be, err) })
	spawn(4, func(i int) { be, err := tbl.PickSticky(toggled, clientOf(i), time.Now()); check(toggled, be, err) })
	spawn(2, func(i int) {
		be, err := tbl.PickStickyCluster(churned, clientOf(i), time.Now())
		check(churned, be, err)
	})
	spawn(2, func(i int) { _ = tbl.transportAddr(netip.AddrPortFrom(netip.AddrFrom4([4]byte{100, 64, 0, 10}), 8080)) })

	// Writers.
	var flips int
	spawn(1, func(int) {
		flips++
		aff := affinityConfig{}
		if flips%2 == 0 {
			aff = clientIPAffinity(time.Hour)
		}
		tbl.SetEndpointsPolicy(toggled, eps(10), trafficCluster, aff)
	})
	spawn(1, func(int) {
		tbl.Delete(churned)
		tbl.SetEndpointsPolicy(churned, eps(20), trafficCluster, clientIPAffinity(time.Hour))
	})
	spawn(1, func(int) {
		tbl.SetTransportOverrides(map[netip.Addr]netip.Addr{netip.AddrFrom4([4]byte{100, 64, 0, 10}): netip.AddrFrom4([4]byte{192, 168, 64, 10})})
		tbl.SetTransportOverrides(nil)
	})
	spawn(1, func(int) { tbl.SweepExpired(time.Now()) })

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
	select {
	case msg := <-fail:
		t.Fatalf("concurrent pick violated the Ready-set invariant: %s", msg)
	default:
	}

	// Count conservation and the purge invariant, read with every goroutine joined.
	sum := 0
	snap := tbl.load()
	for key, binds := range tbl.affinity {
		sum += len(binds)
		st := snap.states[key]
		if st == nil || st.affinityMode != affinityClientIP {
			if len(binds) != 0 {
				t.Fatalf("%s holds %d bindings but its final state is affinity-off or absent (a pick resurrected a purged binding)", key, len(binds))
			}
		}
	}
	if got := tbl.affinityBindings(); got != sum {
		t.Fatalf("affinityCount = %d, summed map cardinality = %d (count conservation broken)", got, sum)
	}
}
