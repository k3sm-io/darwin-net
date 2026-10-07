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

// The ingress datapath tests that need a real hijackable connection: an HTTP/1.1
// Upgrade splices the switched protocol over the client and backend sockets,
// which an in-memory recorder cannot stand in for. The header and 502 tests run
// on fakes in handler_test.go. It needs no privilege; run with:
//
//	CGO_ENABLED=0 go test -tags integration -run '^TestIngressProxyUpgradePassthrough$' ./pkg/ingress/

package ingress

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
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
