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

// The name-length drift guard drives the Go reference resolver against a stub
// on real loopback sockets, and shares nameOfLength with the wire differential
// (differential_integration_test.go). It needs no privilege; run with:
//
//	CGO_ENABLED=0 go test -tags integration -run '^TestShimMaxNameLenMatchesGo$' ./pkg/dns/

package dns

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// nameOfLength builds a hostname of EXACTLY total presentation bytes (no
// trailing dot) whose every label is well under the 63-byte label ceiling, so
// TOTAL length is the only property under test. It ends in ".invalid" (RFC 2606)
// so any fallthrough to a host resolver can never reach a real name. Shared with
// the wire differential's boundary cases.
func nameOfLength(t *testing.T, total int) string {
	t.Helper()
	const suffix = ".invalid"
	name := ""
	for total-len(name)-len(suffix) > 63 {
		name += strings.Repeat("a", 60) + "."
	}
	fill := total - len(name) - len(suffix)
	if fill < 1 {
		t.Fatalf("nameOfLength(%d): cannot build a name that short", total)
	}
	name += strings.Repeat("b", fill) + suffix
	if len(name) != total {
		t.Fatalf("nameOfLength(%d) produced %d bytes", total, len(name))
	}
	return name
}

// TestShimMaxNameLenMatchesGo binds the C shim's `#define K3SM_DNS_MAX_NAME_LEN`
// to the Go reference resolver's real encoding ceiling. The C side cannot import
// the Go bound, and the bound is subtle — the shim stores a candidate WITHOUT a
// trailing dot while queryA encodes ensureFQDN(candidate) WITH one, so the two
// differ by exactly the dot. Rather than restate 253 on the Go side (a second
// hand-written copy is the thing that drifts), this drives the PRODUCTION path:
// the C constant must be the largest length at which the Go resolver still puts
// bytes on the wire, and one more must produce zero exchanges.
//
// It also asserts the C buffer (K3SM_MAX_NAME) can hold a boundary-length name
// plus its NUL, so a future "bump the buffer" edit cannot quietly turn the
// boundary check into a no-op — the C side carries the same coupling as a
// _Static_assert.
//
// See also: TestDNSWireClassificationDifferential
// (differential_integration_test.go) pins the same boundary BEHAVIOURALLY
// against the real dylib, on both engines at once.
func TestShimMaxNameLenMatchesGo(t *testing.T) {
	t.Parallel()
	cMax := shimDefine(t, "K3SM_DNS_MAX_NAME_LEN")
	if buf := shimDefine(t, "K3SM_MAX_NAME"); buf < cMax+1 {
		t.Fatalf("getaddrinfo-shim buffer/boundary drift: #define K3SM_MAX_NAME = %d cannot hold a %d-byte name plus its NUL", buf, cMax)
	}

	stub := newStubDNS(t, map[string]netip.Addr{})
	defer stub.close()

	tests := []struct {
		name      string
		length    int
		wantDials int
	}{
		{
			name:      "a name at the boundary is encodable and reaches the wire",
			length:    cMax,
			wantDials: 1,
		},
		{
			name:      "one byte over the boundary is unencodable and never reaches the wire",
			length:    cMax + 1,
			wantDials: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// dials counts every exchange the resolver attempts. It is written only
			// from the synchronous dial seam on this goroutine, so it needs no lock.
			dials := 0
			counting := withDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
				dials++
				d := net.Dialer{}
				return d.DialContext(ctx, network, stub.addr())
			})
			r, err := NewResolver(stdConfig(), counting, WithTimeout(time.Second))
			if err != nil {
				t.Fatalf("NewResolver: %v", err)
			}
			// Both lengths are a definitive miss here (the stub knows no names); the
			// discriminator is whether the query reached the wire at all.
			addrs, err := r.lookupCandidate(context.Background(), nameOfLength(t, tt.length))
			if err != nil {
				t.Fatalf("lookupCandidate(%d-byte name) err = %v, want a definitive miss", tt.length, err)
			}
			if len(addrs) != 0 {
				t.Fatalf("lookupCandidate(%d-byte name) = %v, want no addresses", tt.length, addrs)
			}
			if dials != tt.wantDials {
				t.Fatalf("getaddrinfo-shim name-length drift: the Go reference made %d exchange(s) for a %d-byte name, want %d — #define K3SM_DNS_MAX_NAME_LEN = %d is not the Go encoder's ceiling",
					dials, tt.length, tt.wantDials, cMax)
			}
		})
	}
}
