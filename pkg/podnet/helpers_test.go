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
	"context"
	"net/netip"
	"sync"
)

// withAliasManager overrides the alias manager (tests inject the rootless fake).
func withAliasManager(a aliasManager) Option {
	return func(n *Network) { n.alias = a }
}

// fakeAliasManager is the rootless aliasManager used by unit tests: it performs no
// syscalls and records calls so a test can assert Setup/Teardown drove the expected
// Ensure/Remove sequence and that teardown leaked no alias. It mirrors the proxy's
// noopAliasManager.
//
// Locking discipline: the call counts are guarded by mu; Ensure/Remove and the test
// accessors all take it.
type fakeAliasManager struct {
	mu      sync.Mutex
	ensured map[netip.Addr]int
	removed map[netip.Addr]int
	// ensureErr, when non-nil, fails every Ensure without recording it.
	ensureErr error
}

// newFakeAliasManager returns a rootless aliasManager that performs no syscalls.
func newFakeAliasManager() *fakeAliasManager {
	return &fakeAliasManager{
		ensured: make(map[netip.Addr]int),
		removed: make(map[netip.Addr]int),
	}
}

// Ensure records the call and succeeds without touching the interface.
func (m *fakeAliasManager) Ensure(_ context.Context, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ensureErr != nil {
		return m.ensureErr
	}
	m.ensured[ip]++
	return nil
}

// failEnsure makes every later Ensure fail with err (nil restores success).
func (m *fakeAliasManager) failEnsure(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureErr = err
}

// Remove records the call and succeeds without touching the interface.
func (m *fakeAliasManager) Remove(_ context.Context, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removed[ip]++
	return nil
}

// ensures reports how many times Ensure was called for ip (test accessor).
func (m *fakeAliasManager) ensures(ip netip.Addr) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensured[ip]
}

// removes reports how many times Remove was called for ip (test accessor).
func (m *fakeAliasManager) removes(ip netip.Addr) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.removed[ip]
}

// liveAliases reports how many addresses were ensured but not yet removed — i.e.
// the alias leak count. A leak-free teardown drives this to zero.
func (m *fakeAliasManager) liveAliases() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	live := 0
	for ip, e := range m.ensured {
		if e > m.removed[ip] {
			live++
		}
	}
	return live
}
