//go:build integration

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

// This test binds real IPv4 sockets on 0.0.0.0 and 127.0.0.1; it needs no
// privilege. Run with:
//
//	CGO_ENABLED=0 go test -tags integration -run TestNodePortWildcardDetectsAnIPv4Holder ./pkg/proxy/

package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
)

// TestNodePortWildcardDetectsAnIPv4Holder proves the NodePort wildcard listener
// is IPv4-only: beside an IPv4-only process already holding *:p, the proxy's
// NodePort bind on p fails with EADDRINUSE, and the reconcile path reports the
// port unbound through its open-failure log and retries. On macOS a dual-stack
// AF_INET6 socket on [::]:p binds beside that holder, so the proxy would
// advertise a port another process serves.
func TestNodePortWildcardDetectsAnIPv4Holder(t *testing.T) {
	holder, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Skipf("no IPv4 wildcard TCP port available: %v", err)
	}
	defer func() { _ = holder.Close() }()
	nodePort := int32(holder.Addr().(*net.TCPAddr).Port)

	const vip = "127.0.0.1"
	clusterPort := freePort(t, vip)
	key := PortKey{ClusterIP: vip, Port: clusterPort, Protocol: netv1.ProtocolTCP}
	sp := &netv1.ServicePort{Port: clusterPort, Protocol: netv1.ProtocolTCP, NodePort: nodePort}

	t.Run("the NodePort bind fails with EADDRINUSE", func(t *testing.T) {
		alias := newNoopAliasManager()
		p := New(NewRoutingTable(netip.Prefix{}), withAliasManager(alias))
		l, err := p.openListener(key, sp)
		if err == nil {
			l.Close()
			t.Fatalf("NodePort bind on *:%d beside an IPv4 holder succeeded, want EADDRINUSE", nodePort)
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("NodePort bind on *:%d = %v, want EADDRINUSE", nodePort, err)
		}
		alias.mu.Lock()
		removed := alias.removed[netip.MustParseAddr(vip)]
		alias.mu.Unlock()
		if removed == 0 {
			t.Fatalf("the failed open left the ClusterIP alias in place")
		}
	})

	t.Run("reconcile reports the port unbound and retries", func(t *testing.T) {
		h := &captureHandler{}
		p := New(NewRoutingTable(netip.Prefix{}), withAliasManager(newNoopAliasManager()), WithLogger(slog.New(h)))
		ctx, cancel := context.WithCancel(context.Background())
		runDone := make(chan struct{})
		go func() { defer close(runDone); _ = p.Run(ctx) }()
		defer func() { cancel(); <-runDone }()

		eps := []netv1.Endpoint{{IP: "127.0.0.1", Port: 9, Ready: true}}
		if err := p.Reconcile(vip, sp, eps); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for !openFailedInUse(h) {
			if time.Now().After(deadline) {
				t.Fatalf("no %q record with EADDRINUSE for NodePort %d", "open service listener; retrying", nodePort)
			}
			time.Sleep(10 * time.Millisecond)
		}
		p.ReconcileDelete(key)
	})
}

// openFailedInUse reports whether h recorded the worker's open-failure error
// carrying EADDRINUSE.
func openFailedInUse(h *captureHandler) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if r.Level != slog.LevelError || r.Message != "open service listener; retrying" {
			continue
		}
		found := false
		r.Attrs(func(a slog.Attr) bool {
			if e, ok := a.Value.Any().(error); ok && a.Key == "err" && errors.Is(e, syscall.EADDRINUSE) {
				found = true
				return false
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}
