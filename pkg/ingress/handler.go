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
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"
)

// backendWarnInterval throttles the backend-down (502) Warn to at most one per
// backend per interval: the 502 path fires per request, so an unthrottled Warn
// would flood the log for the whole duration of a backend outage.
const backendWarnInterval = 30 * time.Second

// backendKey carries the matched Backend from the routing handler to the
// ReverseProxy Rewrite/ErrorHandler through the request context.
type backendKey struct{}

// handler is the L7 datapath: it matches each request in the RouteTable and
// reverse-proxies it to the matched Service ClusterIP VIP via a single stdlib
// httputil.ReverseProxy. No matching rule and no default backend -> 404.
//
// Forwarded-header discipline (the trust boundary of the shared node):
//   - pr.SetXForwarded OVERWRITES X-Forwarded-For with the direct peer — never
//     appends — so a client cannot smuggle a spoofed chain to the backend. It
//     also sets X-Forwarded-Host/-Proto from the inbound request.
//   - Inbound Forwarded (RFC 7239) and X-Real-IP are stripped explicitly:
//     SetXForwarded does not cover them and they are equally spoofable.
//   - The inbound Host is preserved on the outbound request (pr.Out.Host =
//     pr.In.Host): backend virtual hosting depends on it; the dial target is
//     the VIP, not the Host header.
//
// HTTP/1.1 Upgrade (websocket) passes through: httputil.ReverseProxy restores
// the Connection/Upgrade hop-by-hop headers for an upgrade request before
// Rewrite runs and splices the switched protocol.
type handler struct {
	table *RouteTable
	rp    *httputil.ReverseProxy
	log   *slog.Logger

	// warnMu guards warnLast, the per-backend (dial-target-keyed) timestamp of
	// the last backend-down Warn (the 502 throttle). Touched only under warnMu.
	warnMu   sync.Mutex
	warnLast map[string]time.Time
}

// newHandler builds the datapath handler over table.
func newHandler(table *RouteTable, log *slog.Logger) *handler {
	if log == nil {
		log = slog.Default()
	}
	h := &handler{
		table:    table,
		log:      log,
		warnLast: make(map[string]time.Time),
	}
	h.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			be := pr.In.Context().Value(backendKey{}).(Backend)
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = be.AddrPort().String()
			// OVERWRITE X-Forwarded-For with the peer (SetXForwarded never
			// appends) and set X-Forwarded-Host/-Proto from the inbound request.
			pr.SetXForwarded()
			// SetXForwarded covers XFF/XFH/XFP; Forwarded and X-Real-IP are the
			// remaining spoofable identity headers — strip them explicitly.
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Del("X-Real-Ip")
			// Preserve the inbound Host: virtual hosting on the backend depends
			// on it (the dial target above is the VIP, not the Host header).
			pr.Out.Host = pr.In.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// context.Canceled here is the CLIENT going away mid-proxy, not a
			// backend fault — don't spend the backend's warn budget on it.
			if be, ok := r.Context().Value(backendKey{}).(Backend); ok && r.Context().Err() == nil {
				h.warn502(be, err)
			}
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	return h
}

// ServeHTTP routes the request: RouteTable match (host-specific tier, hostless
// tier, default backend) or a router-level 404.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	be, ok := h.table.Match(requestHost(r.Host), r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := context.WithValue(r.Context(), backendKey{}, be)
	h.rp.ServeHTTP(w, r.WithContext(ctx))
}

// warn502 emits the backend-down Warn, throttled to one per backend per
// backendWarnInterval (see the constant). The sampled err is representative,
// not exhaustive — suppressed 502s within the window are counted only by the
// client-visible status.
func (h *handler) warn502(be Backend, err error) {
	key := be.AddrPort().String()
	now := time.Now()
	h.warnMu.Lock()
	last, seen := h.warnLast[key]
	throttled := seen && now.Sub(last) < backendWarnInterval
	if !throttled {
		h.warnLast[key] = now
	}
	h.warnMu.Unlock()
	if throttled {
		return
	}
	h.log.Warn("ingress backend unreachable, returning 502", "backend", key, "err", err)
}

// requestHost extracts the bare lowercase host from a request Host header,
// stripping any port (and IPv6 brackets via SplitHostPort).
func requestHost(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(strings.Trim(hostport, "[]"))
}
