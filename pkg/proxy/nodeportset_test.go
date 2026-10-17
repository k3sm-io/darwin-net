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

package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/tcpseg"
)

// echoDial is a dialBackend whose every backend echoes what it reads until
// the proxy side closes, so a test can tell a live splice from a torn one.
func echoDial(_ *tcpseg.Dialer, _, _ string) (net.Conn, error) {
	near, far := net.Pipe()
	go func() {
		defer far.Close()
		_, _ = io.Copy(far, far)
	}()
	return near, nil
}

// roundTrip writes msg on c and reads it back.
func roundTrip(c net.Conn, msg string) error {
	_ = c.SetDeadline(time.Now().Add(fakeHandledTimeout))
	if _, err := io.WriteString(c, msg); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return errors.New("echo mismatch: " + string(buf))
	}
	return nil
}

// listenerFor returns the most recent fake listener opened on address.
func listenerFor(t *testing.T, rec *recordingNodePortListen, address string) *fakeListener {
	t.Helper()
	deadline := time.Now().Add(fakeHandledTimeout)
	for {
		_, opened := rec.snapshot()
		for i := len(opened) - 1; i >= 0; i-- {
			if opened[i].address == address {
				return opened[i]
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no NodePort listener opened on %s", address)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestNodePortAddressSetSwaps pins the swappable NodePort address set: a
// prepare binds every open NodePort on the new addresses while the old ones
// keep serving; commit closes only the addresses that left the set, without
// touching an established connection; a bind failure anywhere aborts the whole
// swap and leaves the old set in force; and a NodePort opened after a commit
// binds the new set.
func TestNodePortAddressSetSwaps(t *testing.T) {
	t.Parallel()

	local := addrs("100.64.1.1", "127.0.0.1")
	eps := []netv1.Endpoint{{IP: "10.42.0.1", Port: 8080, Ready: true}}

	start := func(t *testing.T, rec *recordingNodePortListen, opts ...Option) *Proxy {
		t.Helper()
		all := append([]Option{
			withAliasManager(newNoopAliasManager()),
			withBinder(fakeBinder{bound: make(chan *fakeListener, 8)}),
			withListenNodePort(rec.listen),
			withDialBackend(echoDial),
		}, opts...)
		p := New(NewRoutingTable(netip.Prefix{}), all...)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); _ = p.Run(ctx) }()
		t.Cleanup(func() { cancel(); <-done })
		return p
	}
	reconcile := func(t *testing.T, p *Proxy, vip string, nodePort int32) {
		t.Helper()
		sp := &netv1.ServicePort{Port: 80, TargetPort: 8080, Protocol: netv1.ProtocolTCP, NodePort: nodePort}
		if err := p.Reconcile(vip, sp, eps); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}

	t.Run("wildcard to local and back, with a connection in flight", func(t *testing.T) {
		t.Parallel()
		rec := &recordingNodePortListen{}
		p := start(t, rec)
		reconcile(t, p, "10.43.0.91", 30091)
		wild := listenerFor(t, rec, ":30091")

		client := wild.connect(t)
		defer client.Close()
		if err := roundTrip(client, "before"); err != nil {
			t.Fatalf("splice through the wildcard: %v", err)
		}

		sw, err := p.PrepareNodePortAddresses(local...)
		if err != nil {
			t.Fatalf("prepare: %v", err)
		}
		mesh := listenerFor(t, rec, "100.64.1.1:30091")
		loop := listenerFor(t, rec, "127.0.0.1:30091")
		if isClosed(wild) {
			t.Fatal("prepare closed the wildcard listener before the commit")
		}
		if err := sw.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
		if !isClosed(wild) {
			t.Fatal("commit left the wildcard listener open: a LAN address still answers")
		}
		if isClosed(mesh) || isClosed(loop) {
			t.Fatal("commit closed a listener of the new set")
		}
		if err := roundTrip(client, "after"); err != nil {
			t.Fatalf("the connection accepted before the swap did not survive it: %v", err)
		}
		if got := p.NodePortAddresses(); !slices.Equal(got, local) {
			t.Fatalf("NodePortAddresses = %v, want %v", got, local)
		}
		if err := sw.Abort(); !errors.Is(err, ErrNodePortSwapDone) {
			t.Fatalf("a second finish = %v, want ErrNodePortSwapDone", err)
		}

		// A NodePort opened under the new set binds it, never the wildcard.
		reconcile(t, p, "10.43.0.92", 30092)
		listenerFor(t, rec, "100.64.1.1:30092")
		listenerFor(t, rec, "127.0.0.1:30092")
		asked, _ := rec.snapshot()
		if slices.Contains(asked, ":30092") {
			t.Fatalf("a NodePort opened after the commit bound the wildcard: %v", asked)
		}

		// And back to every interface.
		if err := p.SetNodePortAddresses(); err != nil {
			t.Fatalf("swap back to the wildcard: %v", err)
		}
		listenerFor(t, rec, ":30091")
		if !isClosed(mesh) || !isClosed(loop) {
			t.Fatal("the swap back left a specific listener open")
		}
	})

	t.Run("a bind failure on any NodePort rolls the whole swap back", func(t *testing.T) {
		t.Parallel()
		rec := &recordingNodePortListen{fail: map[string]bool{"127.0.0.1:30094": true}}
		p := start(t, rec)
		reconcile(t, p, "10.43.0.93", 30093)
		reconcile(t, p, "10.43.0.94", 30094)
		w93 := listenerFor(t, rec, ":30093")
		w94 := listenerFor(t, rec, ":30094")

		if _, err := p.PrepareNodePortAddresses(local...); err == nil {
			t.Fatal("prepare succeeded with an unbindable address; want the whole swap refused")
		}
		_, opened := rec.snapshot()
		for _, l := range opened {
			if l.address != ":30093" && l.address != ":30094" && !isClosed(l) {
				t.Fatalf("the failed prepare left %s open", l.address)
			}
		}
		if isClosed(w93) || isClosed(w94) {
			t.Fatal("the failed prepare closed an old listener")
		}
		if got := p.NodePortAddresses(); len(got) != 0 {
			t.Fatalf("NodePortAddresses after a failed swap = %v, want the wildcard kept", got)
		}
	})

	t.Run("abort closes only what the prepare added", func(t *testing.T) {
		t.Parallel()
		rec := &recordingNodePortListen{}
		p := start(t, rec, WithNodePortAddresses(local...))
		reconcile(t, p, "10.43.0.95", 30095)
		mesh := listenerFor(t, rec, "100.64.1.1:30095")
		sw, err := p.PrepareNodePortAddresses()
		if err != nil {
			t.Fatalf("prepare: %v", err)
		}
		wild := listenerFor(t, rec, ":30095")
		if err := sw.Abort(); err != nil {
			t.Fatalf("abort: %v", err)
		}
		if !isClosed(wild) || isClosed(mesh) {
			t.Fatalf("abort: wildcard closed=%v (want true), old mesh listener closed=%v (want false)", isClosed(wild), isClosed(mesh))
		}
		if got := p.NodePortAddresses(); !slices.Equal(got, local) {
			t.Fatalf("NodePortAddresses after abort = %v, want %v", got, local)
		}
	})
}

// TestNodePortNetwork proves every NodePort bind address is bound IPv4-only:
// the wildcard ":port" as the IPv4 wildcard, an IPv4 address by family.
func TestNodePortNetwork(t *testing.T) {
	for _, tc := range []struct{ address, want string }{
		{":30080", "tcp4"},
		{"127.0.0.1:30080", "tcp4"},
		{"192.0.2.10:30080", "tcp4"},
		{"[::1]:30080", "tcp"},
		{"30080", "tcp4"},
		{"node.example:30080", "tcp4"},
	} {
		if got := nodePortNetwork(tc.address); got != tc.want {
			t.Errorf("nodePortNetwork(%q) = %q, want %q", tc.address, got, tc.want)
		}
	}
}
