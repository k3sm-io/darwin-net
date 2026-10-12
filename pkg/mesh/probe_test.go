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
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"
)

// TestProberDeclaresDeathAfterThreeMisses pins the liveness probe: a new target is
// dead until it answers, it stays alive through two misses, the third declares it
// dead (one callback), and an answer brings it back (one callback).
func TestProberDeclaresDeathAfterThreeMisses(t *testing.T) {
	ping := &scriptedPinger{}
	var mu sync.Mutex
	var changes []bool
	p := newProber(ping, func(_ ProbeTarget, alive bool) {
		mu.Lock()
		changes = append(changes, alive)
		mu.Unlock()
	})
	peer := netip.MustParseAddr("169.254.0.10")
	target := ProbeTarget{Iface: "bridge0", Peer: peer}
	p.SetTargets([]ProbeTarget{target})
	ctx := context.Background()
	miss := errors.New("timeout")
	steps := []struct {
		err   error
		alive bool
	}{
		{miss, false}, {nil, true}, {miss, true}, {miss, true}, {miss, false}, {miss, false}, {nil, true},
	}
	for i, s := range steps {
		ping.set(s.err)
		p.round(ctx)
		if got := p.Alive("bridge0", peer); got != s.alive {
			t.Fatalf("step %d: alive = %v, want %v", i, got, s.alive)
		}
	}
	if !reflect.DeepEqual(changes, []bool{true, false, true}) {
		t.Fatalf("transitions = %v, want [true false true]", changes)
	}
	p.SetTargets(nil)
	if p.Alive("bridge0", peer) {
		t.Fatal("a removed target is still alive")
	}
}

// scriptedPinger answers every echo with one settable result.
type scriptedPinger struct {
	mu  sync.Mutex
	err error
}

func (s *scriptedPinger) set(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *scriptedPinger) Ping(context.Context, netip.Addr, time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}
