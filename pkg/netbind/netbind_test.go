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

package netbind

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

// TestDirectListensSpecificAddr proves the Direct binder opens a listener on
// the SPECIFIC requested address (the loopback ephemeral case tests cover).
// The Netd binder's SCM_RIGHTS adoption path is proven end-to-end by
// pkg/netd's TestProxyClientRoundTrip against an in-process daemon.
func TestDirectListensSpecificAddr(t *testing.T) {
	ln, err := Direct{}.Listen(context.Background(), "tcp", netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("Direct.Listen: %v", err)
	}
	defer ln.Close()
	host, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil || host != "127.0.0.1" {
		t.Fatalf("bound %q, want a 127.0.0.1 listener (err=%v)", ln.Addr(), err)
	}
}
