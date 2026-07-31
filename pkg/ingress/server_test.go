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

package ingress

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// ephemeralBinder satisfies netbind.Binder for rootless tests: it ignores the
// requested port and binds 127.0.0.1:0, recording the listener so the test can
// dial the real bound address.
type ephemeralBinder struct {
	mu  sync.Mutex
	lns []net.Listener
}

func (b *ephemeralBinder) Listen(_ context.Context, network string, addr netip.AddrPort) (net.Listener, error) {
	ln, err := net.Listen(network, net.JoinHostPort(addr.Addr().String(), "0"))
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.lns = append(b.lns, ln)
	b.mu.Unlock()
	return ln, nil
}

func (b *ephemeralBinder) bound() []net.Listener {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]net.Listener(nil), b.lns...)
}

// failBinder always fails, standing in for netd being down / the address not
// yet plumbed.
type failBinder struct{}

func (failBinder) Listen(context.Context, string, netip.AddrPort) (net.Listener, error) {
	return nil, errors.New("boom")
}

// TestIngressServerRunBindDrain exercises the socket layer through the binder
// seam: Run binds via the injected binder, serves the routing handler on the
// real listener, and drains on context cancel; a bind failure surfaces as the
// NAMED ErrBind (the host's retry signal, non-fatal by contract).
func TestIngressServerRunBindDrain(t *testing.T) {
	t.Run("serves and drains on cancel", func(t *testing.T) {
		table := NewRouteTable()
		binder := &ephemeralBinder{}
		s, err := NewServer(table, Config{
			Addr:     netip.MustParseAddr("127.0.0.1"),
			HTTPPort: 80, // the binder rebinds to an ephemeral port; 80 is the host-shaped config
			Binder:   binder,
			Logger:   slog.New(slog.DiscardHandler),
		})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		runErr := make(chan error, 1)
		go func() { runErr <- s.Run(ctx) }()

		var lns []net.Listener
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if lns = binder.bound(); len(lns) == 1 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if len(lns) != 1 {
			t.Fatal("server did not bind through the binder seam")
		}

		// An empty table serving the router-level 404 proves the handler is live
		// on the real listener.
		resp, err := http.Get(fmt.Sprintf("http://%s/", lns[0].Addr()))
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 from the empty router", resp.StatusCode)
		}

		cancel()
		select {
		case err := <-runErr:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Run returned %v, want context.Canceled", err)
			}
		case <-time.After(2 * drainTimeout):
			t.Fatal("Run did not drain after cancel")
		}
	})

	t.Run("bind failure returns the named ErrBind", func(t *testing.T) {
		s, err := NewServer(NewRouteTable(), Config{
			Addr:     netip.MustParseAddr("127.0.0.1"),
			HTTPPort: 80,
			Binder:   failBinder{},
			Logger:   slog.New(slog.DiscardHandler),
		})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		if err := s.Run(context.Background()); !errors.Is(err, ErrBind) {
			t.Fatalf("Run returned %v, want ErrBind", err)
		}
	})

	// The wildcard used to be rejected here; the decision moved to the host
	// assembler (which chooses the address) and to the netd daemon (which still
	// refuses a wildcard bind — pinned by pkg/netd's
	// TestServerBindPortWildcardRejected, deliberately not duplicated here).
	t.Run("wildcard address accepted", func(t *testing.T) {
		s, err := NewServer(NewRouteTable(), Config{
			Addr:     netip.MustParseAddr("0.0.0.0"),
			HTTPPort: 80,
			Logger:   slog.New(slog.DiscardHandler),
		})
		if err != nil {
			t.Fatalf("NewServer rejected the wildcard: %v", err)
		}
		if got := s.cfg.Addr; !got.IsUnspecified() {
			t.Fatalf("cfg.Addr = %v, want the wildcard preserved", got)
		}
	})

	t.Run("config validation fails fast", func(t *testing.T) {
		cases := []struct {
			name string
			cfg  Config
		}{
			// KEEP: relaxing IsUnspecified must not also relax IsValid — a
			// zero Addr would reach net.Listen as "invalid AddrPort".
			{"invalid address rejected", Config{HTTPPort: 80}},
			{"no listener enabled", Config{Addr: netip.MustParseAddr("127.0.0.1")}},
			{"https without cert resolver", Config{Addr: netip.MustParseAddr("127.0.0.1"), HTTPSPort: 443}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if _, err := NewServer(NewRouteTable(), tc.cfg); err == nil {
					t.Fatal("NewServer accepted an invalid config")
				}
			})
		}
	})
}
