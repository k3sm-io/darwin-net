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
	"context"
	"net/netip"
	"sync"
)

// withAliasManager overrides the alias manager (tests inject the rootless fake).
func withAliasManager(a aliasManager) Option {
	return func(p *Proxy) { p.alias = a }
}

// withListenUDP overrides the ClusterIP datagram bind (tests inject an in-memory
// VIP socket).
func withListenUDP(f func(netip.AddrPort) (udpVIPConn, error)) Option {
	return func(p *Proxy) { p.listenUDP = f }
}

// noopAliasManager is the rootless aliasManager unit tests inject: it performs no
// syscalls and records the Ensure/Remove calls so a test can assert the reconcile
// drove the expected sequence without touching lo0. In production the proxy
// aliases VIPs for real (the netd daemon under WithNetdHelper, or the direct lo0
// manager run as root); the rootless tests bind their VIP on 127.0.0.1 — the one
// loopback address bindable without an alias on Darwin — and distinguish VIPs by
// port.
//
// Locking discipline: ensured is guarded by mu; Ensure/Remove and the test
// accessors all take it.
type noopAliasManager struct {
	mu      sync.Mutex
	ensured map[netip.Addr]int
	removed map[netip.Addr]int
}

// newNoopAliasManager returns a rootless aliasManager that performs no syscalls.
func newNoopAliasManager() *noopAliasManager {
	return &noopAliasManager{
		ensured: make(map[netip.Addr]int),
		removed: make(map[netip.Addr]int),
	}
}

// Ensure records the call and succeeds without touching the interface.
func (m *noopAliasManager) Ensure(_ context.Context, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensured[ip]++
	return nil
}

// Remove records the call and succeeds without touching the interface.
func (m *noopAliasManager) Remove(_ context.Context, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removed[ip]++
	return nil
}

// ensures reports how many times Ensure was called for ip (test accessor).
func (m *noopAliasManager) ensures(ip netip.Addr) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensured[ip]
}

// removes reports how many times Remove was called for ip (test accessor).
func (m *noopAliasManager) removes(ip netip.Addr) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.removed[ip]
}
