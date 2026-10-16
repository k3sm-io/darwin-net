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

package netd

import (
	"errors"
	"net/netip"
	"testing"
)

// fakeRawConn is a syscall.RawConn whose Control hands f a fixed descriptor, so the
// bind hook is exercised without a socket.
type fakeRawConn struct {
	fd         uintptr
	controlErr error
}

func (c fakeRawConn) Control(f func(fd uintptr)) error {
	if c.controlErr != nil {
		return c.controlErr
	}
	f(c.fd)
	return nil
}

func (fakeRawConn) Read(func(fd uintptr) bool) error  { return nil }
func (fakeRawConn) Write(func(fd uintptr) bool) error { return nil }

// TestBindPortUDPCoexistsWithAWildcardListenerDecision pins the UDP bind decision
// behind BindPort: a specific address sets SO_REUSEADDR on the socket before bind,
// so it coexists with a wildcard *:53 another process holds (the Internet Sharing
// resolver), and a wildcard address gets no hook, so its bind is unchanged. The
// real-socket half is the integration test of the same name.
func TestBindPortUDPCoexistsWithAWildcardListenerDecision(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		wantSet bool
	}{
		{name: "specific DNS VIP sets SO_REUSEADDR", addr: "10.43.0.10", wantSet: true},
		{name: "specific loopback sets SO_REUSEADDR", addr: "127.0.0.1", wantSet: true},
		{name: "specific IPv6 sets SO_REUSEADDR", addr: "::1", wantSet: true},
		{name: "IPv4 wildcard is unchanged", addr: "0.0.0.0", wantSet: false},
		{name: "IPv6 wildcard is unchanged", addr: "::", wantSet: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var setFDs []int
			ctl := udpBindControl(netip.MustParseAddr(tc.addr), func(fd int) error {
				setFDs = append(setFDs, fd)
				return nil
			})
			if !tc.wantSet {
				if ctl != nil {
					t.Fatalf("udpBindControl(%s) returned a hook, want nil (wildcard bind unchanged)", tc.addr)
				}
				return
			}
			if ctl == nil {
				t.Fatalf("udpBindControl(%s) = nil, want a hook that sets SO_REUSEADDR", tc.addr)
			}
			if err := ctl("udp", tc.addr+":53", fakeRawConn{fd: 7}); err != nil {
				t.Fatalf("control hook: %v", err)
			}
			if len(setFDs) != 1 || setFDs[0] != 7 {
				t.Fatalf("SO_REUSEADDR set on %v, want exactly fd 7", setFDs)
			}
		})
	}
}

// TestUDPBindControlSurfacesErrors proves a failure to reach or configure the
// socket fails the bind rather than binding without the option.
func TestUDPBindControlSurfacesErrors(t *testing.T) {
	errSet := errors.New("setsockopt failed")
	errCtl := errors.New("raw control failed")
	addr := netip.MustParseAddr("10.43.0.10")

	ctl := udpBindControl(addr, func(int) error { return errSet })
	if err := ctl("udp", "10.43.0.10:53", fakeRawConn{fd: 3}); !errors.Is(err, errSet) {
		t.Fatalf("setsockopt failure: got %v, want wrapping %v", err, errSet)
	}

	called := false
	ctl = udpBindControl(addr, func(int) error { called = true; return nil })
	if err := ctl("udp", "10.43.0.10:53", fakeRawConn{controlErr: errCtl}); !errors.Is(err, errCtl) {
		t.Fatalf("raw control failure: got %v, want wrapping %v", err, errCtl)
	}
	if called {
		t.Fatal("setsockopt ran although raw control failed")
	}
}
