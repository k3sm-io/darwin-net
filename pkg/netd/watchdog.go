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
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultSocketCheckInterval is how often Serve re-stats its own listening socket
// path to confirm the daemon is still reachable at it.
//
// 15s is chosen against the restart path, not against detection latency for its
// own sake: the daemon recovers by exiting so launchd's KeepAlive restarts it, and
// launchd throttles a restart to no sooner than 10s after the previous start, so
// polling faster than that cannot shorten the outage. 15s keeps the black-hole
// window comfortably inside the interval a client spends retrying a failed dial,
// and costs one stat(2) per interval — unmeasurable next to the daemon's ordinary
// per-request syscall work.
const DefaultSocketCheckInterval = 15 * time.Second

// ErrSocketLost is returned by Serve when the unix socket file it is listening on
// has been removed or replaced by a different filesystem object. It is the crash-
// only exit signal described on the watchdog: the daemon cannot serve anyone
// through an unlinked inode, so it stops and lets launchd start it clean.
var ErrSocketLost = errors.New("netd: listening socket removed or replaced")

// socketIdentity is the (device, inode) pair naming the filesystem object a unix
// listener is bound to. It is the identity the watchdog compares, because a path
// alone cannot distinguish "still my socket" from "someone unlinked mine and bound
// a new one at the same name": the second netd's socket has the same path and a
// different inode.
//
// The listener's own fd is deliberately not the reference. fstat(2) on an AF_UNIX
// socket fd reports the socket's inode, not the inode of the filesystem entry it
// was bound to, so it is not comparable with a stat(2) of the path; the baseline is
// therefore taken by stat'ing the path once when Serve starts.
type socketIdentity struct {
	dev uint64
	ino uint64
}

// statSocketIdentity returns the identity of the filesystem object at path.
func statSocketIdentity(path string) (socketIdentity, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return socketIdentity{}, err
	}
	return socketIdentity{dev: uint64(st.Dev), ino: st.Ino}, nil
}

// checkSocketPath re-stats path and compares it against the identity recorded when
// the listener was adopted. It returns nil while the socket is intact, an error
// wrapping ErrSocketLost once the path is gone or names a different object, and a
// plain (non-ErrSocketLost) error for a stat failure that does not prove either —
// the caller logs those and keeps watching rather than killing a working daemon on
// a transient stat.
func checkSocketPath(path string, want socketIdentity) error {
	got, err := statSocketIdentity(path)
	switch {
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTDIR):
		return fmt.Errorf("%w: %s no longer exists: %v", ErrSocketLost, path, err)
	case err != nil:
		return fmt.Errorf("stat %s: %w", path, err)
	case got != want:
		return fmt.Errorf("%w: %s is now dev %d inode %d, was dev %d inode %d",
			ErrSocketLost, path, got.dev, got.ino, want.dev, want.ino)
	}
	return nil
}

// startSocketWatchdog arms the crash-only socket watchdog for l. It is a logged
// no-op for a listener that is not a unix socket with a filesystem path, and for a
// path that cannot be stat'ed at start — the watchdog exists to notice a socket
// that disappears later, and refusing to serve because a baseline stat failed would
// trade a recoverable gap for an outage.
//
// On detection the watchdog sends the error to lost (buffered, so it never blocks)
// and then closes l, which fails the pending Accept; Serve prefers the reported
// error over the resulting "use of closed network connection".
func (s *Server) startSocketWatchdog(ctx context.Context, l net.Listener, stop <-chan struct{}, lost chan<- error) {
	ua, ok := l.Addr().(*net.UnixAddr)
	if !ok || ua.Name == "" {
		s.log.Debug("netd: socket watchdog disabled (listener is not a path-bound unix socket)")
		return
	}
	path := ua.Name
	if abs, err := filepath.Abs(path); err == nil {
		// Resolve once, so a later working-directory change cannot turn the poll
		// into a stat of some other path (or of nothing).
		path = abs
	}
	want, err := statSocketIdentity(path)
	if err != nil {
		s.log.Warn("netd: socket watchdog disabled (cannot stat listening socket)", "path", path, "err", err)
		return
	}

	interval := s.cfg.SocketCheckInterval
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-t.C:
			}
			err := checkSocketPath(path, want)
			if err == nil {
				continue
			}
			if !errors.Is(err, ErrSocketLost) {
				s.log.Warn("netd: cannot stat listening socket", "path", path, "err", err)
				continue
			}
			s.log.Error("netd: listening socket removed or replaced; exiting so launchd restarts the daemon",
				"path", path, "err", err)
			select {
			case lost <- err:
			default:
			}
			_ = l.Close()
			return
		}
	}()
	s.log.Debug("netd: socket watchdog armed", "path", path, "interval", interval)
}
