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
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// backendFromURL converts an httptest server URL into the Backend that dials it.
func backendFromURL(t *testing.T, raw string) Backend {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}
	ap, err := netip.ParseAddrPort(u.Host)
	if err != nil {
		t.Fatalf("parse backend hostport: %v", err)
	}
	return Backend{VIP: ap.Addr(), Port: ap.Port()}
}

// recordedRequest is what the fake backend observed.
type recordedRequest struct {
	host   string
	header http.Header
}

// TestIngressProxyHeaderDiscipline is the M10.3 datapath gate, end-to-end
// through real 127.0.0.1:0 listeners: the backend must see X-Forwarded-For
// OVERWRITTEN with the direct peer (a spoofed inbound chain is gone, never
// appended to), inbound Forwarded / X-Real-IP stripped, and the inbound Host
// preserved (virtual hosting). An unrouted host gets the router-level 404.
func TestIngressProxyHeaderDiscipline(t *testing.T) {
	var (
		mu  sync.Mutex
		got recordedRequest
	)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = recordedRequest{host: r.Host, header: r.Header.Clone()}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	table := NewRouteTable()
	table.Update([]Rule{{
		Host: "app.example.com", Path: "/", PathType: PathTypePrefix,
		Backend: backendFromURL(t, backend.URL),
	}}, nil)
	front := httptest.NewServer(newHandler(table, slog.New(slog.DiscardHandler)))
	defer front.Close()

	req, err := http.NewRequest(http.MethodGet, front.URL+"/some/path", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "app.example.com" // routed virtual host, preserved to the backend
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("Forwarded", "for=203.0.113.9")
	req.Header.Set("X-Real-IP", "203.0.113.9")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	mu.Lock()
	defer mu.Unlock()
	if got.host != "app.example.com" {
		t.Errorf("backend saw Host %q, want app.example.com (inbound Host must be preserved)", got.host)
	}
	if xff := got.header.Get("X-Forwarded-For"); xff != "127.0.0.1" {
		t.Errorf("backend saw X-Forwarded-For %q, want exactly the peer 127.0.0.1 (overwrite, never append)", xff)
	}
	if v, present := got.header["Forwarded"]; present {
		t.Errorf("inbound Forwarded header reached the backend: %v", v)
	}
	if v, present := got.header["X-Real-Ip"]; present {
		t.Errorf("inbound X-Real-IP header reached the backend: %v", v)
	}
	if xfh := got.header.Get("X-Forwarded-Host"); xfh != "app.example.com" {
		t.Errorf("backend saw X-Forwarded-Host %q, want app.example.com", xfh)
	}
	if xfp := got.header.Get("X-Forwarded-Proto"); xfp != "http" {
		t.Errorf("backend saw X-Forwarded-Proto %q, want http", xfp)
	}

	t.Run("unrouted host gets the router 404", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, front.URL+"/some/path", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Host = "unknown.example.com"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
	})
}

// TestIngressProxyBackend502Throttled proves a down backend yields 502 to every
// client while the backend-down Warn is throttled to one per backend per
// interval (the per-request path must not flood the log during an outage).
func TestIngressProxyBackend502Throttled(t *testing.T) {
	// A port that refuses connections: bind, capture, close.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAP := netip.MustParseAddrPort(ln.Addr().String())
	_ = ln.Close()

	var logBuf bytes.Buffer
	var logMu sync.Mutex
	log := slog.New(slog.NewTextHandler(lockedWriter{&logMu, &logBuf}, nil))

	table := NewRouteTable()
	table.Update([]Rule{{
		Host: "app.example.com", Path: "/", PathType: PathTypePrefix,
		Backend: Backend{VIP: deadAP.Addr(), Port: deadAP.Port()},
	}}, nil)
	front := httptest.NewServer(newHandler(table, log))
	defer front.Close()

	for i := 0; i < 3; i++ {
		req, err := http.NewRequest(http.MethodGet, front.URL+"/", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Host = "app.example.com"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("request %d: status = %d, want 502", i, resp.StatusCode)
		}
	}
	logMu.Lock()
	warns := strings.Count(logBuf.String(), "ingress backend unreachable")
	logMu.Unlock()
	if warns != 1 {
		t.Fatalf("backend-down Warn fired %d times for 3 requests within the interval, want exactly 1", warns)
	}
}

// lockedWriter serializes test-log writes so -race stays quiet across the
// handler's request goroutines.
type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// TestIngressProxyUpgradePassthrough proves an HTTP/1.1 Upgrade (the websocket
// shape) passes through the stdlib ReverseProxy datapath: the 101 reaches the
// client and bytes flow both ways on the switched protocol.
func TestIngressProxyUpgradePassthrough(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "echo" {
			http.Error(w, "expected upgrade", http.StatusBadRequest)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
		_ = rw.Flush()
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		_, _ = rw.WriteString(line)
		_ = rw.Flush()
	}))
	defer backend.Close()

	table := NewRouteTable()
	table.Update([]Rule{{
		Host: "up.example.com", Path: "/", PathType: PathTypePrefix,
		Backend: backendFromURL(t, backend.URL),
	}}, nil)
	front := httptest.NewServer(newHandler(table, slog.New(slog.DiscardHandler)))
	defer front.Close()

	conn, err := net.DialTimeout("tcp", front.Listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial front: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: up.example.com\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if _, err := fmt.Fprintf(conn, "ping over switched protocol\n"); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	echoed, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if echoed != "ping over switched protocol\n" {
		t.Fatalf("echoed %q", echoed)
	}
}
