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

// The resolver test that needs the kernel: a connected-UDP exchange with a
// closed loopback port gets ECONNREFUSED from the kernel's ICMP handling, which
// an in-memory fake would only restate. The rest of the resolver's wire path
// runs on fakeDNS in resolver_test.go. It needs no privilege; run with:
//
//	CGO_ENABLED=0 go test -tags integration -run '^TestLookupHostClosedPortIsTempFail$' ./pkg/dns/

package dns

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestLookupHostClosedPortIsTempFail points the resolver at a closed loopback
// port: a connected-UDP exchange gets an immediate ECONNREFUSED, which is a
// TRANSIENT failure (ErrTempFail), never ErrNotFound — the Go analog of the
// shim's EAI_AGAIN when the cluster resolver is unreachable.
func TestLookupHostClosedPortIsTempFail(t *testing.T) {
	t.Parallel()
	// Reserve then release a loopback UDP port so it is (near-certainly) closed.
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("reserve closed port: %v", err)
	}
	closedAddr := c.LocalAddr().String()
	_ = c.Close()

	dialClosed := withDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, network, closedAddr)
	})
	r, err := NewResolver(stdConfig(), dialClosed, WithTimeout(300*time.Millisecond))
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	_, err = r.LookupHost(context.Background(), "web")
	if !errors.Is(err, ErrTempFail) {
		t.Fatalf("LookupHost against a closed port err = %v, want ErrTempFail", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("ECONNREFUSED collapsed into ErrNotFound: %v", err)
	}
}
