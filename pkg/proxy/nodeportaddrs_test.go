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
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// recordingNodePortListen is a fake listenNodePort: it records every address
// asked for, opens an in-memory listener for it, and fails the addresses named
// in fail. Locking discipline: every field is guarded by mu.
type recordingNodePortListen struct {
	mu     sync.Mutex
	fail   map[string]bool
	asked  []string
	opened []*fakeListener
}

func (r *recordingNodePortListen) listen(network, address string) (net.Listener, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asked = append(r.asked, address)
	if r.fail[address] {
		return nil, errors.New("fake bind failure")
	}
	l := newFakeListener(network, address)
	r.opened = append(r.opened, l)
	return l, nil
}

func (r *recordingNodePortListen) snapshot() ([]string, []*fakeListener) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.asked), slices.Clone(r.opened)
}

func isClosed(l *fakeListener) bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// TestNodePortBindsConfiguredAddresses is the gate for the NodePort address set
// (the kube-proxy --nodeport-addresses analog): a spec resolves to host
// addresses once, every NodePort binds each of them instead of the wildcard,
// all or nothing, and releases them all when the Service goes away. With no
// setting the NodePort still binds the wildcard, as upstream does.
func TestNodePortBindsConfiguredAddresses(t *testing.T) {
	t.Parallel()

	const nodePort = 30090
	node := netip.MustParseAddr("100.64.1.1")
	// A LAN-shaped address, a mesh address on a utun, and a link-local one: what
	// HostAddrs might report on a joined Mac.
	host := addrs("127.0.0.1", "192.0.2.10", "100.64.1.1", "169.254.3.4", "fe80::1")

	t.Run("resolution", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name string
			spec string
			node netip.Addr
			want []netip.Addr
		}{
			{"empty spec is the wildcard", "", node, nil},
			{"blank spec is the wildcard", "  ", node, nil},
			{"loopback CIDR selects loopback", "127.0.0.0/8", node, addrs("127.0.0.1")},
			{"mesh CIDR selects the mesh address", "100.64.0.0/10", node, addrs("100.64.1.1")},
			{"a host CIDR selects the LAN address", "192.0.2.0/24", node, addrs("192.0.2.10")},
			{"a list unions and sorts", "192.0.2.0/24, 127.0.0.0/8", node, addrs("127.0.0.1", "192.0.2.10")},
			{"preset is loopback plus the node address", "local", node, addrs("100.64.1.1", "127.0.0.1")},
			{"preset dedupes against a CIDR", "local,127.0.0.1/32", node, addrs("100.64.1.1", "127.0.0.1")},
			{"preset with no node address is loopback", "local", netip.Addr{}, addrs("127.0.0.1")},
			{"the node address counts before it is aliased", "100.64.2.0/24", netip.MustParseAddr("100.64.2.1"), addrs("100.64.2.1")},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := ResolveNodePortAddresses(tc.spec, tc.node, host)
				if err != nil {
					t.Fatalf("ResolveNodePortAddresses(%q): %v", tc.spec, err)
				}
				if !slices.Equal(got, tc.want) {
					t.Fatalf("ResolveNodePortAddresses(%q) = %v, want %v", tc.spec, got, tc.want)
				}
			})
		}
	})

	t.Run("unusable specs are refused by name", func(t *testing.T) {
		t.Parallel()
		for _, spec := range []string{"lan", "192.0.2.10", "::1/128", "127.0.0.0/8,", "10.99.0.0/16"} {
			if got, err := ResolveNodePortAddresses(spec, node, host); !errors.Is(err, ErrNodePortAddresses) {
				t.Errorf("ResolveNodePortAddresses(%q) = %v, %v; want ErrNodePortAddresses", spec, got, err)
			}
		}
		// Syntax alone, for a caller that records the spec for later: a range
		// that selects nothing HERE is valid; a malformed entry never is.
		for spec, ok := range map[string]bool{"": true, "local": true, "10.99.0.0/16, local": true, "lan": false, "::1/128": false, "127.0.0.0/8,": false} {
			if err := ValidateNodePortAddresses(spec); (err == nil) != ok {
				t.Errorf("ValidateNodePortAddresses(%q) = %v, want ok=%v", spec, err, ok)
			}
		}
	})

	// run starts a proxy with the recording listen and returns it plus a stop.
	run := func(t *testing.T, rec *recordingNodePortListen, opts ...Option) *Proxy {
		t.Helper()
		binder := fakeBinder{bound: make(chan *fakeListener, 8)}
		all := append([]Option{
			withAliasManager(newNoopAliasManager()),
			withBinder(binder),
			withListenNodePort(rec.listen),
		}, opts...)
		p := New(NewRoutingTable(netip.Prefix{}), all...)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); _ = p.Run(ctx) }()
		t.Cleanup(func() { cancel(); <-done })
		return p
	}
	sp := &netv1.ServicePort{Port: 80, TargetPort: 8080, Protocol: netv1.ProtocolTCP, NodePort: nodePort}
	eps := []netv1.Endpoint{{IP: "10.42.0.1", Port: 8080, Ready: true}}
	key := PortKey{ClusterIP: "10.43.0.90", Port: 80, Protocol: netv1.ProtocolTCP}

	waitOpened := func(t *testing.T, rec *recordingNodePortListen, n int) ([]string, []*fakeListener) {
		t.Helper()
		deadline := time.Now().Add(fakeHandledTimeout)
		for {
			asked, opened := rec.snapshot()
			if len(opened) >= n {
				return asked, opened
			}
			if time.Now().After(deadline) {
				t.Fatalf("NodePort listeners opened = %d (asked %v), want %d", len(opened), asked, n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	t.Run("default binds the wildcard", func(t *testing.T) {
		t.Parallel()
		rec := &recordingNodePortListen{}
		p := run(t, rec)
		if err := p.Reconcile(key.ClusterIP, sp, eps); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		asked, _ := waitOpened(t, rec, 1)
		if want := []string{":30090"}; !slices.Equal(asked, want) {
			t.Fatalf("NodePort binds = %q, want %q", asked, want)
		}
	})

	t.Run("a configured set binds each address and releases them on removal", func(t *testing.T) {
		t.Parallel()
		set, err := ResolveNodePortAddresses(NodePortPresetLocal, node, host)
		if err != nil {
			t.Fatal(err)
		}
		rec := &recordingNodePortListen{}
		p := run(t, rec, WithNodePortAddresses(set...))
		if err := p.Reconcile(key.ClusterIP, sp, eps); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		asked, opened := waitOpened(t, rec, 2)
		if want := []string{"100.64.1.1:30090", "127.0.0.1:30090"}; !slices.Equal(asked, want) {
			t.Fatalf("NodePort binds = %q, want %q (never the wildcard, never the LAN address)", asked, want)
		}
		p.ReconcileDelete(key)
		for _, l := range opened {
			select {
			case <-l.done:
			case <-time.After(fakeHandledTimeout):
				t.Fatalf("ReconcileDelete left the NodePort listener on %s open", l.address)
			}
		}
	})

	t.Run("a partial bind is rolled back", func(t *testing.T) {
		t.Parallel()
		rec := &recordingNodePortListen{fail: map[string]bool{"127.0.0.1:30090": true}}
		p := New(NewRoutingTable(netip.Prefix{}),
			withAliasManager(newNoopAliasManager()),
			withBinder(fakeBinder{bound: make(chan *fakeListener, 1)}),
			withListenNodePort(rec.listen),
			WithNodePortAddresses(addrs("100.64.1.1", "127.0.0.1")...))
		l, err := p.openListener(key, sp)
		if err == nil {
			l.Close()
			t.Fatal("openListener succeeded with one NodePort address unbindable; want all or nothing")
		}
		asked, opened := rec.snapshot()
		if want := []string{"100.64.1.1:30090", "127.0.0.1:30090"}; !slices.Equal(asked, want) {
			t.Fatalf("NodePort binds = %q, want %q", asked, want)
		}
		if len(opened) != 1 || !isClosed(opened[0]) {
			t.Fatalf("the NodePort listener bound before the failure was not closed: %d opened", len(opened))
		}
	})
}
