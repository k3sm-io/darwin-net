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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

// failingBind is a conn.Bind whose every Send fails with err, the way the real
// bind reports a sendmsg failure (a *net.OpError over an *os.SyscallError).
type failingBind struct {
	conn.Bind
	err error
}

func (b failingBind) Send([][]byte, conn.Endpoint) error {
	return &net.OpError{Op: "write", Net: "udp4", Err: os.NewSyscallError("sendmsg", b.err)}
}

// sendFails drives one wireguard send to dst through the device's send-watch
// bind with the given errno, then runs whatever refresh it queued, on this
// goroutine, so the outcome is deterministic.
func sendFails(t *testing.T, d *WGDevice, dst string, errno error) {
	t.Helper()
	b := &sendWatchBind{Bind: failingBind{err: errno}, onUnreachable: d.noteUnreachable}
	ep := &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort(dst)}
	if err := b.Send([][]byte{{0}}, ep); err == nil {
		t.Fatal("failingBind.Send returned nil")
	}
	select {
	case q := <-d.failures:
		d.refreshUnreachable(q)
	default:
	}
}

// deviceView renders the UAPI "get" reply of a device holding nodeB's key at
// endpoint, with a handshake at hs (zero: never).
func deviceView(key, endpoint string, hs time.Time) string {
	var sec, nsec int64
	if !hs.IsZero() {
		sec, nsec = hs.Unix(), int64(hs.Nanosecond())
	}
	return fmt.Sprintf("private_key=00\nlisten_port=51820\npublic_key=%s\nendpoint=%s\nlast_handshake_time_sec=%d\nlast_handshake_time_nsec=%d\ntx_bytes=0\nrx_bytes=0\npersistent_keepalive_interval=25\nallowed_ip=100.64.1.0/24\nprotocol_version=1\n",
		key, endpoint, sec, nsec)
}

// TestPeerEndpointFollowsRegisteredChange is the gate for a peer that changed
// address: the device must end up sending to the endpoint the registry (the
// MeshPeer) holds, promptly, whether the registry moved or the address the
// device was sending to went dead.
//
// Each row starts from a device that has applied and settled nodeB at the
// registered endpoint A, then optionally lets wireguard roam the peer
// (roamedTo), then applies the registry steps in order, then optionally makes
// one send fail. It asserts what the LAST wireguard write said about nodeB's
// endpoint (or that nothing was written) and whether the registry owner was
// asked to re-read.
//
// Fails-before: the rows where a send to a dead roamed endpoint fails left the
// device on that endpoint until the peer itself sent again, because the
// roaming contract only re-stamped a registered endpoint the registry had
// changed. The registry-change rows pin that a MeshPeer endpoint change is
// written on the very next apply.
func TestPeerEndpointFollowsRegisteredChange(t *testing.T) {
	const (
		epA = "192.0.2.10:51820"
		epB = "192.0.2.20:51820"
		epR = "198.51.100.30:51820"
	)
	tests := []struct {
		name       string
		roamedTo   string   // wireguard roamed nodeB here before the steps; "" = still at A
		registry   []string // registered endpoints applied in order after the settle
		failDst    string   // a send to this endpoint fails after the steps; "" = none
		failErr    error
		wantWrite  string // the endpoint the last write re-stamped; "" = assert no new write
		wantNotify bool
	}{
		{name: "registry moves: the next apply writes the new endpoint", registry: []string{epB}, wantWrite: epB},
		{name: "registry moves away and back: the last value is written", registry: []string{epB, epA}, wantWrite: epA},
		{name: "registry moves while wireguard had roamed elsewhere", roamedTo: epR, registry: []string{epB}, wantWrite: epB},
		{name: "roamed endpoint host down: the registered one is re-applied", roamedTo: epR, failDst: epR, failErr: unix.EHOSTDOWN, wantWrite: epA, wantNotify: true},
		{name: "roamed endpoint has no route: the registered one is re-applied", roamedTo: epR, failDst: epR, failErr: unix.ENETUNREACH, wantWrite: epA, wantNotify: true},
		{name: "roamed endpoint unreachable then registry moves", roamedTo: epR, registry: []string{epB}, failDst: epB, failErr: unix.EHOSTUNREACH, wantNotify: true},
		{name: "registered endpoint host down: nothing to rewrite, ask for a re-read", failDst: epA, failErr: unix.EHOSTDOWN, wantNotify: true},
		{name: "a full buffer is not an unreachable peer", roamedTo: epR, failDst: epR, failErr: unix.ENOBUFS},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			d, wg, _ := applierDevice(t)
			var notified []string
			d.cfg.onUnreachable = func(node string) { notified = append(notified, node) }
			key := keyHex(t, 0x42)

			plan := peerPlan(t, epA)
			for i := 0; i < 2; i++ { // the full write, then the first incremental one
				if err := d.Apply(ctx, plan); err != nil {
					t.Fatalf("settle Apply: %v", err)
				}
			}
			view := epA
			if tc.roamedTo != "" {
				view = tc.roamedTo
			}
			wg.status = deviceView(key, view, time.Time{})
			for _, ep := range tc.registry {
				if err := d.Apply(ctx, peerPlan(t, ep)); err != nil {
					t.Fatalf("Apply registry %s: %v", ep, err)
				}
				// The write just stamped ep, so the device now sends there.
				wg.status = deviceView(key, ep, time.Time{})
			}
			before := len(wg.sets)
			if tc.failDst != "" {
				sendFails(t, d, tc.failDst, tc.failErr)
			}

			if tc.wantWrite == "" {
				if len(wg.sets) != before {
					t.Fatalf("wrote %q after the send failure, want no wireguard write", wg.sets[before:])
				}
			} else {
				if len(wg.sets) == before && tc.failDst != "" {
					t.Fatalf("no wireguard write after the send failure, want nodeB re-stamped at %s", tc.wantWrite)
				}
				last := wg.sets[len(wg.sets)-1]
				if !strings.Contains(last, "public_key="+key+"\nendpoint="+tc.wantWrite+"\n") {
					t.Fatalf("last write = %q, want nodeB re-stamped at %s", last, tc.wantWrite)
				}
				if strings.Contains(last, "replace_peers=true") {
					t.Fatalf("last write = %q, a re-stamp must be incremental", last)
				}
			}
			if got := len(notified) > 0; got != tc.wantNotify {
				t.Fatalf("registry re-read requested = %v (%v), want %v", got, notified, tc.wantNotify)
			}
			if tc.wantNotify && notified[0] != "nodeB" {
				t.Fatalf("re-read requested for %q, want nodeB", notified[0])
			}
		})
	}
}

// TestUnreachableRefreshIsRateLimited pins the bound: a dead endpoint fails on
// every packet, and only one re-application per UnreachableRefreshInterval per
// destination may follow.
func TestUnreachableRefreshIsRateLimited(t *testing.T) {
	const (
		epA = "192.0.2.10:51820"
		epR = "198.51.100.30:51820"
	)
	ctx := context.Background()
	d, wg, _ := applierDevice(t)
	now := time.Unix(1_800_000_000, 0)
	d.now = func() time.Time { return now }
	notified := 0
	d.cfg.onUnreachable = func(string) { notified++ }
	key := keyHex(t, 0x42)
	plan := peerPlan(t, epA)
	if err := d.Apply(ctx, plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	wg.status = deviceView(key, epR, time.Time{})

	sendFails(t, d, epR, unix.EHOSTDOWN)
	writes := len(wg.sets)
	if notified != 1 {
		t.Fatalf("first failure: %d re-read requests, want 1", notified)
	}
	// wireguard roams back to R (the peer sent from it once more), and the
	// failures keep coming inside the interval.
	for i := 0; i < 10; i++ {
		now = now.Add(UnreachableRefreshInterval / 20)
		sendFails(t, d, epR, unix.EHOSTDOWN)
	}
	if len(wg.sets) != writes || notified != 1 {
		t.Fatalf("inside the interval: %d writes, %d requests after the first, want 0 and 0", len(wg.sets)-writes, notified-1)
	}
	now = now.Add(UnreachableRefreshInterval)
	sendFails(t, d, epR, unix.EHOSTDOWN)
	if len(wg.sets) != writes+1 || notified != 2 {
		t.Fatalf("after the interval: %d writes, %d requests, want 1 more of each", len(wg.sets)-writes, notified)
	}
}

// TestUnreachableRefreshFailedWriteForcesFullResync pins that a failed re-stamp
// leaves the device as a failed Apply does: the next apply is a full resync.
func TestUnreachableRefreshFailedWriteForcesFullResync(t *testing.T) {
	ctx := context.Background()
	d, wg, _ := applierDevice(t)
	plan := peerPlan(t, "192.0.2.10:51820")
	if err := d.Apply(ctx, plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	wg.status = deviceView(keyHex(t, 0x42), "198.51.100.30:51820", time.Time{})
	wg.setErr = errors.New("ipc: boom")
	sendFails(t, d, "198.51.100.30:51820", unix.EHOSTDOWN)
	wg.setErr = nil
	if err := d.Apply(ctx, plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if last := wg.sets[len(wg.sets)-1]; !strings.Contains(last, "replace_peers=true\n") {
		t.Fatalf("apply after a failed re-stamp wrote %q, want the full resync", last)
	}
}

// TestPeerStatusReportsHandshakeAge pins the handshake age the device reports
// and logs on every apply: the age since the peer's last completed handshake,
// "never" when there has been none, with the node name from the plan.
func TestPeerStatusReportsHandshakeAge(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	key := keyHex(t, 0x42)
	tests := []struct {
		name      string
		handshake time.Time
		wantAge   time.Duration
		wantOK    bool
		wantLog   string
	}{
		{name: "recent handshake", handshake: now.Add(-12*time.Second - 300*time.Millisecond), wantAge: 12*time.Second + 300*time.Millisecond, wantOK: true, wantLog: "nodeB=12s"},
		{name: "stale handshake", handshake: now.Add(-15 * time.Minute), wantAge: 15 * time.Minute, wantOK: true, wantLog: "nodeB=15m0s"},
		{name: "never", wantLog: "nodeB=never"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, wg, _ := applierDevice(t)
			d.now = func() time.Time { return now }
			if err := d.Apply(ctx, peerPlan(t, "192.0.2.10:51820")); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			wg.status = deviceView(key, "192.0.2.10:51820", tc.handshake)
			peers, err := d.PeerStatus()
			if err != nil {
				t.Fatalf("PeerStatus: %v", err)
			}
			if len(peers) != 1 || peers[0].NodeName != "nodeB" || peers[0].Endpoint != "192.0.2.10:51820" {
				t.Fatalf("PeerStatus = %+v, want nodeB at its endpoint", peers)
			}
			age, ok := peers[0].HandshakeAge(now)
			if ok != tc.wantOK || age != tc.wantAge {
				t.Fatalf("HandshakeAge = %v, %v; want %v, %v", age, ok, tc.wantAge, tc.wantOK)
			}
			d.mu.Lock()
			got := d.handshakeSummaryLocked()
			d.mu.Unlock()
			if len(got) != 1 || got[0] != tc.wantLog {
				t.Fatalf("handshake summary = %q, want [%q]", got, tc.wantLog)
			}
		})
	}
}

// TestParsePeerStatusRejectsMalformedHandshake pins that a garbled handshake
// time is an error rather than a made-up age.
func TestParsePeerStatusRejectsMalformedHandshake(t *testing.T) {
	if _, err := parsePeerStatus("public_key=ab\nlast_handshake_time_sec=x\n"); err == nil {
		t.Fatal("parsePeerStatus accepted a non-numeric handshake time")
	}
	if got, err := parsePeerStatus(""); err != nil || len(got) != 0 {
		t.Fatalf("parsePeerStatus(\"\") = %v, %v; want none, nil", got, err)
	}
}

// TestWatcherReReadsRegistryOnUnreachable pins the direct-device path: a peer
// found unreachable re-reads the MeshPeer snapshot at once, not at the next
// resync tick, so an endpoint the peer already published is applied now.
func TestWatcherReReadsRegistryOnUnreachable(t *testing.T) {
	w, fake := newTestWatcher(t)
	seedPeer(t, w, "nodeB", "100.64.1.0/24", "192.0.2.20:51820", 0x42, "7")
	_, stop := startLoop(t, w)
	defer stop()

	w.mesh.requestRefresh("nodeB")
	waitForApplies(t, fake, 1)
	if got := fake.last().Peers[0].Endpoint; got != "192.0.2.20:51820" {
		t.Fatalf("re-read applied endpoint %q, want the registered 192.0.2.20:51820", got)
	}
}
