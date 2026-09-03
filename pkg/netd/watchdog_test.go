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

package netd_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"k3sm.io/darwin-net/pkg/netd"
	"k3sm.io/darwin-net/pkg/netd/wire"
)

// watchdogInterval is the injected poll period for the socket watchdog in these
// tests. Production uses netd.DefaultSocketCheckInterval.
const watchdogInterval = 20 * time.Millisecond

// startWatchedServer starts Serve on a fresh unix socket with the watchdog interval
// injected, proves the daemon is live with one round trip, and returns the socket
// path plus the channel carrying Serve's return value. Cleanup cancels and waits
// for Serve regardless of whether the test already consumed its return value, so a
// test that expects Serve to exit on its own needs no teardown of its own.
func startWatchedServer(t *testing.T) (string, <-chan error) {
	t.Helper()
	sock := tempSock(t)
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sock, err)
	}
	srv := netd.NewServer(netd.Config{
		NodePodCIDR:         netip.MustParsePrefix("100.64.0.0/24"),
		ServiceUID:          uint32(os.Getuid()),
		Privileged:          &fakePriv{},
		SocketCheckInterval: watchdogInterval,
	})
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		served <- srv.Serve(ctx, l)
		close(finished)
	}()
	t.Cleanup(func() {
		cancel()
		_ = l.Close()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Errorf("Serve did not return within 5s of cancellation")
		}
	})

	// One completed round trip: the daemon is serving before the test disturbs its
	// socket, so an exit afterwards cannot be mistaken for a failure to start.
	if err := wire.NewClient(sock).EnsureAlias(context.Background(), netip.MustParseAddr("100.64.0.2")); err != nil {
		t.Fatalf("pre-disturbance EnsureAlias: %v", err)
	}
	return sock, served
}

// requireSocketLostExit waits for Serve to return and asserts it exited on the
// watchdog verdict rather than on any other path.
func requireSocketLostExit(t *testing.T, served <-chan error) {
	t.Helper()
	select {
	case err := <-served:
		if !errors.Is(err, netd.ErrSocketLost) {
			t.Fatalf("Serve returned %v, want an error wrapping netd.ErrSocketLost", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return within 5s of its socket being removed or replaced; the daemon is accepting on an unreachable inode and launchd cannot restart it")
	}
}

// requireStillServing asserts Serve has NOT returned (checked without waiting —
// callers sleep for the watchdog ticks they want covered first).
func requireStillServing(t *testing.T, served <-chan error) {
	t.Helper()
	select {
	case err := <-served:
		t.Fatalf("Serve returned %v while its socket was intact; the watchdog fired on a healthy daemon", err)
	default:
	}
}

// TestServeExitsWhenItsSocketIsReplaced proves the crash-only watchdog fires when
// the socket FILE the daemon is bound to is swapped for a different object at the
// same path. The listener keeps working on the old, now-unlinked inode, so nothing
// in the accept path can notice: only the (device, inode) identity check does. The
// sanctioned recovery is to exit and let launchd's KeepAlive rebind.
func TestServeExitsWhenItsSocketIsReplaced(t *testing.T) {
	tests := []struct {
		name    string
		replace func(t *testing.T, path string)
	}{
		{
			name: "a second netd unlinks and rebinds the path",
			replace: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatalf("remove socket: %v", err)
				}
				l, err := net.Listen("unix", path)
				if err != nil {
					t.Fatalf("second listen: %v", err)
				}
				t.Cleanup(func() { _ = l.Close() })
			},
		},
		{
			name: "the path is replaced by a regular file",
			replace: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatalf("remove socket: %v", err)
				}
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatalf("write regular file: %v", err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sock, served := startWatchedServer(t)
			tc.replace(t, sock)
			requireSocketLostExit(t, served)
		})
	}
}

// TestServeExitsWhenItsSocketIsRemoved is the sibling case: a stray rm or a
// run-directory cleanup unlinks the socket and puts nothing back. Every subsequent
// client dial fails with ENOENT while launchd still reports the job running, so the
// daemon must notice and exit rather than serve an inode nobody can reach.
func TestServeExitsWhenItsSocketIsRemoved(t *testing.T) {
	sock, served := startWatchedServer(t)
	if err := os.Remove(sock); err != nil {
		t.Fatalf("remove socket: %v", err)
	}
	requireSocketLostExit(t, served)
}

// TestServeKeepsServingAnUndisturbedSocket is the non-vacuity guard: with the
// watchdog polling aggressively, a daemon whose socket is untouched must keep
// accepting. Without it, a watchdog that fired on every tick would still pass both
// tests above while making the daemon unusable.
func TestServeKeepsServingAnUndisturbedSocket(t *testing.T) {
	const ticks = 10
	sock, served := startWatchedServer(t)
	time.Sleep(ticks * watchdogInterval)
	requireStillServing(t, served)

	if err := wire.NewClient(sock).EnsureAlias(context.Background(), netip.MustParseAddr("100.64.0.3")); err != nil {
		t.Fatalf("EnsureAlias after ~%d watchdog ticks on an intact socket: %v", ticks, err)
	}
}
