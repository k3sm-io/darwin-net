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
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"k3sm.io/darwin-net/pkg/netbind"
)

// ErrBind is the NAMED bind failure returned by Server.Run before any serving
// starts. The HOST treats it as non-fatal and owns the retry policy (the node
// address may not be plumbed yet, netd may not be up); this package never
// retries a bind itself.
var ErrBind = errors.New("ingress: bind listener")

// drainTimeout bounds the graceful http.Server.Shutdown on context cancel: in-
// flight requests get this long to complete, then remaining connections are
// closed hard. Kept short — the ingress fronts local VIPs, not slow WAN peers.
const drainTimeout = 5 * time.Second

// Config configures a Server. The HOST decides the port policy (80/443 vs a
// high-port dev config) — there is no fallback logic here: the
// configured ports are bound or Run fails with ErrBind.
type Config struct {
	// Addr is the node address to bind. It must be a valid address; the
	// WILDCARD (0.0.0.0) IS accepted, so a host that needs the L7 listener to
	// answer on every node interface can ask for it explicitly.
	//
	// This package used to reject the wildcard here, because a wildcard L7
	// listener on the shared node is a cross-tenant footgun. That rationale
	// still holds — the DECISION moved rather than the concern going away, to
	// the two places that can actually make it:
	//
	//   - the HOST assembler, which now chooses the bind address (and,
	//     separately, the address it advertises). Denying the wildcard from
	//     inside this constructor only hid the choice; it never made the node
	//     less shared.
	//   - the root netd daemon, which STILL refuses a wildcard bind outright
	//     (pkg/netd handleBindPort, pinned by
	//     pkg/netd::TestServerBindPortWildcardRejected — not duplicated here).
	//     So a wildcard can never be laundered through the privileged helper:
	//     in helper mode (Binder is netbind.Netd) a wildcard Addr constructs
	//     fine and then fails at Run with ErrBind.
	Addr netip.Addr
	// HTTPPort is the plaintext HTTP port; 0 disables the HTTP listener.
	HTTPPort uint16
	// HTTPSPort is the TLS port; 0 disables the TLS listener. When set, Certs
	// must be non-nil.
	HTTPSPort uint16
	// Binder opens the listening sockets. In helper mode the host passes the
	// shared netd binder (netbind.Netd) and EVERY ingress bind goes through the
	// daemon — no local-bind split for the node-address listener. Nil means
	// netbind.Direct (tests, explicit run-as-root).
	Binder netbind.Binder
	// Certs resolves SNI hosts to certificates for the TLS listener.
	Certs CertResolver
	// Logger is the structured log sink; nil means slog.Default.
	Logger *slog.Logger
}

// Server is the L7 socket layer: it binds the configured HTTP/HTTPS listeners
// on the configured node address (the wildcard included) through the netbind
// seam and serves the routing handler, draining gracefully when its context is
// cancelled.
type Server struct {
	cfg     Config
	binder  netbind.Binder
	handler http.Handler
	log     *slog.Logger
}

// NewServer builds a Server routing via table. It validates the config
// eagerly: a fail-fast construction error is a misconfiguration (fix the
// config), unlike the retryable runtime ErrBind from Run.
func NewServer(table *RouteTable, cfg Config) (*Server, error) {
	if table == nil {
		return nil, errors.New("ingress: nil route table")
	}
	// Only VALIDITY is checked: the wildcard is a legal choice for the host to
	// make (see Config.Addr), but the zero Addr is not — it would otherwise
	// reach net.Listen as the literal string "invalid AddrPort".
	if !cfg.Addr.IsValid() {
		return nil, fmt.Errorf("ingress: config requires a valid node address, got %q", cfg.Addr)
	}
	if cfg.HTTPPort == 0 && cfg.HTTPSPort == 0 {
		return nil, errors.New("ingress: config enables no listener (both ports zero)")
	}
	if cfg.HTTPSPort != 0 && cfg.Certs == nil {
		return nil, errors.New("ingress: https port set but no cert resolver")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	binder := cfg.Binder
	if binder == nil {
		binder = netbind.Direct{}
	}
	return &Server{
		cfg:     cfg,
		binder:  binder,
		handler: newHandler(table, log),
		log:     log,
	}, nil
}

// Run binds the configured listeners, serves until ctx is cancelled, then
// drains gracefully (http.Server.Shutdown bounded by drainTimeout) and returns
// ctx.Err(). A bind failure is returned immediately wrapped in ErrBind (any
// already-bound listener is closed); a serve failure after a successful bind is
// returned as-is. Mirrors the proxy/netserve run-loop shape: goroutine per
// listener, one error channel, single owner of the sockets' lifetime.
func (s *Server) Run(ctx context.Context) error {
	type bound struct {
		scheme string
		ln     net.Listener
	}
	var listeners []bound
	closeAll := func() {
		for _, b := range listeners {
			_ = b.ln.Close()
		}
	}

	if s.cfg.HTTPPort != 0 {
		ln, err := s.bind(ctx, s.cfg.HTTPPort)
		if err != nil {
			return err
		}
		listeners = append(listeners, bound{"http", ln})
	}
	if s.cfg.HTTPSPort != 0 {
		ln, err := s.bind(ctx, s.cfg.HTTPSPort)
		if err != nil {
			closeAll()
			return err
		}
		listeners = append(listeners, bound{"https", tls.NewListener(ln, serverTLSConfig(s.cfg.Certs))})
	}
	for _, b := range listeners {
		s.log.Info("ingress listener bound", "scheme", b.scheme, "addr", b.ln.Addr().String())
	}

	srv := &http.Server{Handler: s.handler}
	errc := make(chan error, len(listeners))
	for _, b := range listeners {
		go func(ln net.Listener) { errc <- srv.Serve(ln) }(b.ln)
	}

	select {
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		defer cancel()
		if err := srv.Shutdown(shCtx); err != nil {
			// Drain deadline exceeded: close remaining connections hard.
			_ = srv.Close()
		}
		for range listeners {
			<-errc // every Serve returns http.ErrServerClosed after Shutdown/Close
		}
		return ctx.Err()
	case err := <-errc:
		// A listener died out from under us; tear the rest down and surface it.
		_ = srv.Close()
		for i := 1; i < len(listeners); i++ {
			<-errc
		}
		return fmt.Errorf("ingress serve: %w", err)
	}
}

// bind opens one listener on cfg.Addr:port through the binder seam.
func (s *Server) bind(ctx context.Context, port uint16) (net.Listener, error) {
	ap := netip.AddrPortFrom(s.cfg.Addr, port)
	ln, err := s.binder.Listen(ctx, "tcp", ap)
	if err != nil {
		return nil, fmt.Errorf("%w %s: %w", ErrBind, ap, err)
	}
	return ln, nil
}
