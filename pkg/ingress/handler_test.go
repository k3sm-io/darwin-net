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
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// The handler's datapath tests run on fakes: the request enters through
// ServeHTTP with an httptest.Recorder, and the handler's ReverseProxy Transport
// is replaced by a fakeTransport, so the outbound request is inspected without a
// socket. The Upgrade passthrough needs a hijackable connection and lives in
// handler_integration_test.go.

// fakeTransport is an http.RoundTripper standing in for the backend dial. It
// records every outbound request and answers with status, or fails with err.
type fakeTransport struct {
	status int
	err    error

	mu  sync.Mutex
	got []*http.Request // the outbound requests, guarded by mu
}

func (f *fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.got = append(f.got, r.Clone(r.Context()))
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return &http.Response{
		StatusCode: f.status,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    r,
	}, nil
}

func (f *fakeTransport) requests() []*http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*http.Request(nil), f.got...)
}

// fakeHandler builds the datapath handler over table with its backend dial
// replaced by rt.
func fakeHandler(table *RouteTable, log *slog.Logger, rt http.RoundTripper) *handler {
	h := newHandler(table, log)
	h.rp.Transport = rt
	return h
}

// TestIngressProxyHeaderDiscipline is the datapath header gate: the backend must
// see X-Forwarded-For OVERWRITTEN with the direct peer (a spoofed inbound chain
// is gone, never appended to), inbound Forwarded / X-Real-IP stripped, the
// inbound Host preserved (virtual hosting), and the request sent to the matched
// backend VIP. An unrouted host gets the router-level 404 and never reaches a
// backend.
func TestIngressProxyHeaderDiscipline(t *testing.T) {
	backend := Backend{VIP: netip.MustParseAddr("10.43.0.17"), Port: 8080}
	table := NewRouteTable()
	table.Update([]Rule{{
		Host: "app.example.com", Path: "/", PathType: PathTypePrefix,
		Backend: backend,
	}}, nil)
	rt := &fakeTransport{status: http.StatusOK}
	h := fakeHandler(table, slog.New(slog.DiscardHandler), rt)

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/some/path", nil)
	req.RemoteAddr = "198.51.100.7:40312" // the direct peer
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("Forwarded", "for=203.0.113.9")
	req.Header.Set("X-Real-IP", "203.0.113.9")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	reqs := rt.requests()
	if len(reqs) != 1 {
		t.Fatalf("backend saw %d requests, want 1", len(reqs))
	}
	got := reqs[0]
	if got.URL.Host != "10.43.0.17:8080" || got.URL.Scheme != "http" {
		t.Errorf("outbound URL = %s, want http://10.43.0.17:8080 (the matched backend VIP)", got.URL)
	}
	if got.URL.Path != "/some/path" {
		t.Errorf("outbound path = %q, want /some/path", got.URL.Path)
	}
	if got.Host != "app.example.com" {
		t.Errorf("backend saw Host %q, want app.example.com (inbound Host must be preserved)", got.Host)
	}
	if xff := got.Header.Get("X-Forwarded-For"); xff != "198.51.100.7" {
		t.Errorf("backend saw X-Forwarded-For %q, want exactly the peer 198.51.100.7 (overwrite, never append)", xff)
	}
	if v, present := got.Header["Forwarded"]; present {
		t.Errorf("inbound Forwarded header reached the backend: %v", v)
	}
	if v, present := got.Header["X-Real-Ip"]; present {
		t.Errorf("inbound X-Real-IP header reached the backend: %v", v)
	}
	if xfh := got.Header.Get("X-Forwarded-Host"); xfh != "app.example.com" {
		t.Errorf("backend saw X-Forwarded-Host %q, want app.example.com", xfh)
	}
	if xfp := got.Header.Get("X-Forwarded-Proto"); xfp != "http" {
		t.Errorf("backend saw X-Forwarded-Proto %q, want http", xfp)
	}

	t.Run("unrouted host gets the router 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/some/path", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
		if n := len(rt.requests()); n != 1 {
			t.Fatalf("backend saw %d requests after the unrouted one, want still 1", n)
		}
	})
}

// TestIngressProxyBackend502Throttled proves a down backend yields 502 to every
// client while the backend-down Warn is throttled to one per backend per
// interval (the per-request path must not flood the log during an outage).
func TestIngressProxyBackend502Throttled(t *testing.T) {
	var logBuf bytes.Buffer
	var logMu sync.Mutex
	log := slog.New(slog.NewTextHandler(lockedWriter{&logMu, &logBuf}, nil))

	table := NewRouteTable()
	table.Update([]Rule{{
		Host: "app.example.com", Path: "/", PathType: PathTypePrefix,
		Backend: Backend{VIP: netip.MustParseAddr("10.43.0.18"), Port: 80},
	}}, nil)
	rt := &fakeTransport{err: errors.New("dial tcp 10.43.0.18:80: connect: connection refused")}
	h := fakeHandler(table, log, rt)

	for i := range 3 {
		req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("request %d: status = %d, want 502", i, rec.Code)
		}
	}
	if n := len(rt.requests()); n != 3 {
		t.Fatalf("backend dial attempted %d times, want 3", n)
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
