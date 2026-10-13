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
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"

	"k3sm.io/darwin-net/pkg/tcpseg"
)

// ErrNodePortSwapDone is returned by NodePortSwap.Commit and Abort on a swap
// that was already committed or aborted.
var ErrNodePortSwapDone = errors.New("nodeport address swap already finished")

// nodePortSet is the address set every NodePort listener binds, together with
// every NodePort listener group currently open, so the set can be swapped for
// all of them at once (PrepareNodePortAddresses).
//
// Locking discipline: mu guards addrs and groups and every group's listener
// map. It is a leaf lock: nothing calls back into the proxy while holding it.
// A prepared swap HOLDS mu until its Commit or Abort, so the set cannot change
// underneath it and no NodePort opens on a set that is about to be replaced; a
// worker opening a NodePort meanwhile waits for the swap to finish.
type nodePortSet struct {
	mu     sync.Mutex
	addrs  []netip.Addr
	groups map[*nodePortGroup]struct{}
	listen func(network, address string) (net.Listener, error)
}

// nodePortGroup is the open listeners of one NodePort: one per bind address
// (the wildcard ":port", or one "a.b.c.d:port" per configured address), each
// served by serve.
type nodePortGroup struct {
	set   *nodePortSet
	port  int32
	serve func(net.Listener)
	lns   map[string]net.Listener
}

// newNodePortSet builds the set with the configured addresses (empty is the
// wildcard) and the bind call.
func newNodePortSet(addrs []netip.Addr, listen func(network, address string) (net.Listener, error)) *nodePortSet {
	return &nodePortSet{addrs: slices.Clone(addrs), groups: make(map[*nodePortGroup]struct{}), listen: listen}
}

// bindAddrs is where a NodePort listens under addrs: the wildcard ":port" when
// addrs is empty, or one "addr:port" per address.
func bindAddrs(addrs []netip.Addr, nodePort int32) []string {
	port := strconv.Itoa(int(nodePort))
	if len(addrs) == 0 {
		return []string{net.JoinHostPort("", port)}
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, net.JoinHostPort(a.String(), port))
	}
	return out
}

// bindAll binds every address in want, all or nothing: on a failure the
// listeners already opened are closed before it returns. Each listener clamps
// its TCP segment size.
func (s *nodePortSet) bindAll(want []string) (map[string]net.Listener, error) {
	out := make(map[string]net.Listener, len(want))
	for _, addr := range want {
		raw, err := s.listen("tcp", addr)
		if err != nil {
			closeListeners(out)
			return nil, fmt.Errorf("listen nodePort %s: %w", addr, err)
		}
		out[addr] = tcpseg.WrapListener(raw)
	}
	return out, nil
}

// closeListeners closes every listener in lns. Closing a listener stops new
// connections only: connections it already accepted keep running.
func closeListeners(lns map[string]net.Listener) {
	for _, l := range lns {
		_ = l.Close()
	}
}

// open binds every listener of one NodePort on the current set, all or
// nothing, starts serve on each and registers the group for later swaps.
func (s *nodePortSet) open(nodePort int32, serve func(net.Listener)) (*nodePortGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lns, err := s.bindAll(bindAddrs(s.addrs, nodePort))
	if err != nil {
		return nil, err
	}
	g := &nodePortGroup{set: s, port: nodePort, serve: serve, lns: lns}
	for _, l := range lns {
		go serve(l)
	}
	s.groups[g] = struct{}{}
	return g, nil
}

// close closes every listener of the group and unregisters it. A nil group is
// a no-op.
func (g *nodePortGroup) close() {
	if g == nil {
		return
	}
	g.set.mu.Lock()
	defer g.set.mu.Unlock()
	closeListeners(g.lns)
	g.lns = nil
	delete(g.set.groups, g)
}

// current returns a copy of the committed set (empty is the wildcard).
func (s *nodePortSet) current() []netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.addrs)
}

// NodePortSwap is a prepared change of the NodePort address set: every open
// NodePort already listens on the new addresses as well as the old ones.
// Commit closes the addresses that left the set; Abort closes the ones the
// prepare added and keeps the old set. Exactly one of them must be called, and
// promptly: the swap holds the set's lock, so a NodePort that opens meanwhile
// waits for it.
type NodePortSwap struct {
	set   *nodePortSet
	addrs []netip.Addr
	// added is, per group, the listeners the prepare opened.
	added map[*nodePortGroup]map[string]net.Listener
	once  sync.Once
}

// PrepareNodePortAddresses starts swapping the address set every NodePort
// listener binds for addrs (empty is the wildcard, every interface). It binds
// each open NodePort on the addresses it does not yet listen on, all or
// nothing across every NodePort: on any bind failure the listeners it opened
// are closed, the old set stays in force and the error names the address. On
// success the old listeners are still open until Commit.
//
// Wildcard and specific listeners of one port coexist on Darwin (both carry
// SO_REUSEADDR), so a swap between the two never leaves a port unbound.
// Closing a listener never closes the connections it accepted. Invalid
// addresses are dropped, as WithNodePortAddresses does.
func (p *Proxy) PrepareNodePortAddresses(addrs ...netip.Addr) (*NodePortSwap, error) {
	var want []netip.Addr
	for _, a := range addrs {
		if a.IsValid() {
			want = append(want, a.Unmap())
		}
	}
	s := p.np
	s.mu.Lock()
	sw := &NodePortSwap{set: s, addrs: want, added: make(map[*nodePortGroup]map[string]net.Listener)}
	for g := range s.groups {
		var missing []string
		for _, addr := range bindAddrs(want, g.port) {
			if _, ok := g.lns[addr]; !ok {
				missing = append(missing, addr)
			}
		}
		lns, err := s.bindAll(missing)
		if err != nil {
			for _, opened := range sw.added {
				closeListeners(opened)
			}
			s.mu.Unlock()
			return nil, err
		}
		for _, l := range lns {
			go g.serve(l)
		}
		sw.added[g] = lns
	}
	return sw, nil
}

// Commit makes the prepared set the one in force: every NodePort closes its
// listeners on addresses outside it (their accepted connections keep running)
// and a NodePort that opens from now on binds the new set.
func (sw *NodePortSwap) Commit() error {
	return sw.finish(true)
}

// Abort drops the prepared set: the listeners the prepare opened are closed
// and the old set stays in force.
func (sw *NodePortSwap) Abort() error {
	return sw.finish(false)
}

// finish is Commit (keep) or Abort, at most once, releasing the set's lock.
func (sw *NodePortSwap) finish(keep bool) error {
	err := ErrNodePortSwapDone
	sw.once.Do(func() {
		err = nil
		s := sw.set
		defer s.mu.Unlock()
		if !keep {
			for _, opened := range sw.added {
				closeListeners(opened)
			}
			return
		}
		for g := range s.groups {
			want := bindAddrs(sw.addrs, g.port)
			for addr, l := range g.lns {
				if !slices.Contains(want, addr) {
					_ = l.Close()
					delete(g.lns, addr)
				}
			}
			for addr, l := range sw.added[g] {
				g.lns[addr] = l
			}
		}
		s.addrs = sw.addrs
	})
	return err
}

// SetNodePortAddresses swaps the NodePort address set in one step:
// PrepareNodePortAddresses, then Commit. On a bind failure nothing changes.
func (p *Proxy) SetNodePortAddresses(addrs ...netip.Addr) error {
	sw, err := p.PrepareNodePortAddresses(addrs...)
	if err != nil {
		return err
	}
	return sw.Commit()
}

// NodePortAddresses returns the address set in force for NodePort listeners;
// empty means the wildcard (every interface).
func (p *Proxy) NodePortAddresses() []netip.Addr {
	return p.np.current()
}
