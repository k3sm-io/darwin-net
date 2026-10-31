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

package mesh

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"k8s.io/client-go/rest"
)

// handshakeDevice is a fakeDevice that reports a fixed handshake time per peer
// public key and signals every completed Apply on applied.
type handshakeDevice struct {
	fakeDevice
	seen    map[string]time.Time
	applied chan struct{}
}

func (d *handshakeDevice) Apply(ctx context.Context, p Plan) error {
	if err := d.fakeDevice.Apply(ctx, p); err != nil {
		return err
	}
	d.applied <- struct{}{}
	return nil
}

func (d *handshakeDevice) PeerHandshakes(context.Context) (map[string]time.Time, error) {
	return d.seen, nil
}

// blockingStatus is a status writer whose every write blocks until release is
// closed or the write's context ends. The first write closes entered, and
// every write records whether its context carried a deadline.
type blockingStatus struct {
	entered     chan struct{}
	release     chan struct{}
	writes      int
	noDeadlines int
}

func (b *blockingStatus) patch(ctx context.Context, _ string, _ []byte) error {
	b.writes++
	if _, ok := ctx.Deadline(); !ok {
		b.noDeadlines++
	}
	if b.writes == 1 {
		close(b.entered)
	}
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TestStatusWriteDoesNotDelayReconcile pins that a MeshPeer status write never
// stands between a peer-set change and the reconcile that programs it. A
// status write that hangs (a slow apiserver) is held open, a second MeshPeer
// arrives, and the reconcile for it must run within a bound shorter than the
// status write's own timeout, so it is the decoupling, not the timeout, that
// lets it through. Every status write must also carry a deadline.
//
// Fails-before: resync PATCHed each peer's status inline after Reconcile on
// the reconcile loop's goroutine, with no per-call timeout, so the second
// reconcile waited for the hung write and AllowedIPs for the new peer were not
// programmed until the apiserver answered.
func TestStatusWriteDoesNotDelayReconcile(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dev := &handshakeDevice{
			seen:    map[string]time.Time{strings.ToLower(keyHex(t, 0x42)): time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)},
			applied: make(chan struct{}, 4),
		}
		m, err := New(netip.MustParsePrefix("100.64.0.0/24"), withDevice(dev), WithLogger(discardLogger()))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		w, err := NewWatcher(&rest.Config{Host: "https://127.0.0.1:1"}, m, discardLogger(), WithHandshakeStatus())
		if err != nil {
			t.Fatalf("NewWatcher: %v", err)
		}
		st := &blockingStatus{entered: make(chan struct{}), release: make(chan struct{})}
		w.patchStatus = st.patch
		seedPeer(t, w, "nodeB", "100.64.1.0/24", "192.0.2.10:51820", 0x42, "1")

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- w.reconcileLoop(ctx, nil) }()

		// The first pass programs nodeB, and its status write for nodeB hangs.
		w.trigger()
		<-dev.applied
		<-st.entered

		// A peer-set change lands while the status write is still hanging.
		seedPeer(t, w, "nodeC", "100.64.2.0/24", "192.0.2.11:51820", 0x43, "1")
		w.trigger()

		// The bound is fake time inside the bubble: it advances only once every
		// goroutine is blocked, so a reconcile that is stuck behind the status
		// write trips it at once and a reconcile that is free never sees it.
		const bound = time.Second
		timer := time.NewTimer(bound)
		select {
		case <-dev.applied:
			if got := len(dev.last().Peers); got != 2 {
				t.Errorf("the reconcile after the change applied %d peers, want 2", got)
			}
		case <-timer.C:
			t.Errorf("a peer-set change was not reconciled within %v while a MeshPeer status write hung; the status write is on the reconcile path", bound)
		}
		timer.Stop()

		close(st.release)
		cancel()
		if err := <-done; err != context.Canceled {
			t.Errorf("reconcileLoop returned %v, want context.Canceled", err)
		}
		if st.noDeadlines != 0 {
			t.Errorf("%d of %d MeshPeer status writes ran with no deadline", st.noDeadlines, st.writes)
		}
	})
}
