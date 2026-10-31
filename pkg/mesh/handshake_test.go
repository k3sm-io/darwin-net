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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/netd/wire"
)

// statusRecorder records the status patches a Watcher writes.
type statusRecorder struct {
	mu      sync.Mutex
	patches map[string][]string
}

func (r *statusRecorder) patch(_ context.Context, name string, body []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.patches == nil {
		r.patches = map[string][]string{}
	}
	r.patches[name] = append(r.patches[name], string(body))
	return nil
}

func (r *statusRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, ps := range r.patches {
		n += len(ps)
	}
	return n
}

// TestApplyWritesPeerHandshakeTime is the gate for writing MeshPeer
// status.lastHandshakeTime from the control-plane node's own wireguard view:
// after a reconcile pass applies the plan, the watcher reads the device's
// per-peer handshakes (the UAPI get, parsed) and merge-patches the status
// subresource of each MeshPeer whose handshake is newer than the recorded one.
// A peer with no handshake, this node's own MeshPeer, and an unchanged
// handshake write nothing, and a watcher built without WithHandshakeStatus
// (a worker) writes nothing at all.
//
// Fails-before: nothing wrote MeshPeer status, so the REACHABLE and handshake
// columns stayed blank whatever the tunnel did.
func TestApplyWritesPeerHandshakeTime(t *testing.T) {
	handshake := time.Date(2026, 10, 30, 12, 0, 5, 250_000_000, time.UTC)
	build := func(t *testing.T, opts ...WatcherOption) (*Watcher, *fakeWG, *statusRecorder) {
		t.Helper()
		dev, wg, _ := applierDevice(t)
		m, err := New(netip.MustParsePrefix("100.64.0.0/24"), withDevice(dev), WithLogger(discardLogger()))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		w, err := NewWatcher(&rest.Config{Host: "https://127.0.0.1:1"}, m, discardLogger(), opts...)
		if err != nil {
			t.Fatalf("NewWatcher: %v", err)
		}
		rec := &statusRecorder{}
		if w.patchStatus != nil {
			w.patchStatus = rec.patch
		}
		seedPeer(t, w, "server", "100.64.0.0/24", "192.0.2.1:51820", 0x01, "1")
		seedPeer(t, w, "nodeB", "100.64.1.0/24", "192.0.2.2:51820", 0x42, "1")
		seedPeer(t, w, "nodeC", "100.64.2.0/24", "192.0.2.3:51820", 0x43, "1")
		wg.get = fmt.Sprintf("private_key=%s\nlisten_port=51820\n"+
			"public_key=%s\nendpoint=192.0.2.2:51820\nlast_handshake_time_sec=%d\nlast_handshake_time_nsec=%d\nallowed_ip=100.64.1.0/24\n"+
			"public_key=%s\nendpoint=192.0.2.3:51820\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\nallowed_ip=100.64.2.0/24\n"+
			"errno=0\n",
			keyHex(t, 0x07), keyHex(t, 0x42), handshake.Unix(), handshake.Nanosecond(), keyHex(t, 0x43))
		return w, wg, rec
	}

	t.Run("server writes the handshake of the peer that has one", func(t *testing.T) {
		w, _, rec := build(t, WithHandshakeStatus())
		w.resync(context.Background())
		if got := rec.count(); got != 1 {
			t.Fatalf("first pass wrote %d status patches (%v), want 1, for nodeB only", got, rec.patches)
		}
		ps := rec.patches["nodeB"]
		if len(ps) != 1 {
			t.Fatalf("nodeB patches = %v, want exactly one", rec.patches)
		}
		var body struct {
			Status map[string]json.RawMessage `json:"status"`
		}
		if err := json.Unmarshal([]byte(ps[0]), &body); err != nil {
			t.Fatalf("decode patch %q: %v", ps[0], err)
		}
		if len(body.Status) != 1 {
			t.Fatalf("patch %q touches %d status fields, want only lastHandshakeTime", ps[0], len(body.Status))
		}
		var got metav1.Time
		if err := json.Unmarshal(body.Status["lastHandshakeTime"], &got); err != nil {
			t.Fatalf("decode lastHandshakeTime in %q: %v", ps[0], err)
		}
		if want := handshake.Truncate(time.Second); !got.Time.Equal(want) {
			t.Fatalf("lastHandshakeTime = %s, want %s", got.Time, want)
		}
	})

	t.Run("an unchanged handshake is not rewritten", func(t *testing.T) {
		w, _, rec := build(t, WithHandshakeStatus())
		obj, ok, err := w.informer.GetStore().GetByKey("nodeB")
		if err != nil || !ok {
			t.Fatalf("nodeB not in the store: %v", err)
		}
		mp := obj.(*netv1.MeshPeer).DeepCopy()
		mt := metav1.NewTime(handshake.Truncate(time.Second))
		mp.Status.LastHandshakeTime = &mt
		mp.ResourceVersion = "2"
		if err := w.informer.GetStore().Update(mp); err != nil {
			t.Fatalf("update store: %v", err)
		}
		w.resync(context.Background())
		if got := rec.count(); got != 0 {
			t.Fatalf("a pass with the handshake already recorded wrote %d patches (%v), want 0", got, rec.patches)
		}
	})

	t.Run("a worker watcher writes no status", func(t *testing.T) {
		w, _, _ := build(t)
		if w.patchStatus != nil {
			t.Fatal("a watcher built without WithHandshakeStatus has a status writer")
		}
		w.resync(context.Background())
	})
}

// TestParseHandshakes pins the UAPI get parser: never-handshaken peers are left
// out, nanoseconds are kept, keys are lowercased, and a peer with a malformed
// key or time is dropped and counted while the others are still returned.
func TestParseHandshakes(t *testing.T) {
	good, other := keyHex(t, 0x42), keyHex(t, 0x43)
	peer := func(key, sec, nsec string) string {
		return fmt.Sprintf("public_key=%s\nlast_handshake_time_sec=%s\nlast_handshake_time_nsec=%s\n", key, sec, nsec)
	}
	cases := []struct {
		name    string
		in      string
		want    map[string]time.Time
		skipped int
	}{
		{"one peer", peer(good, "10", "7"), map[string]time.Time{good: time.Unix(10, 7).UTC()}, 0},
		{"uppercase key", peer(strings.ToUpper(good), "10", "0"), map[string]time.Time{good: time.Unix(10, 0).UTC()}, 0},
		{"never handshaken", peer(good, "0", "0"), map[string]time.Time{}, 0},
		{"bad key is skipped", peer("zz", "10", "0") + peer(other, "11", "0"), map[string]time.Time{other: time.Unix(11, 0).UTC()}, 1},
		{"short key is skipped", peer("abcd", "10", "0") + peer(other, "11", "0"), map[string]time.Time{other: time.Unix(11, 0).UTC()}, 1},
		{"bad seconds are skipped", peer(good, "x", "0") + peer(other, "11", "0"), map[string]time.Time{other: time.Unix(11, 0).UTC()}, 1},
		{"negative seconds are skipped", peer(good, "-1", "0") + peer(other, "11", "0"), map[string]time.Time{other: time.Unix(11, 0).UTC()}, 1},
		{"nanoseconds out of range are skipped", peer(good, "10", "1000000000") + peer(other, "11", "0"), map[string]time.Time{other: time.Unix(11, 0).UTC()}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, skipped, err := ParseHandshakes(tc.in)
			if err != nil {
				t.Fatalf("ParseHandshakes: %v", err)
			}
			if skipped != tc.skipped || len(got) != len(tc.want) {
				t.Fatalf("ParseHandshakes = %v (skipped %d), want %v (skipped %d)", got, skipped, tc.want, tc.skipped)
			}
			for k, w := range tc.want {
				if !got[k].Equal(w) {
					t.Fatalf("ParseHandshakes[%s] = %s, want %s", k, got[k], w)
				}
			}
		})
	}
	if _, _, err := ParseHandshakes(strings.Repeat("x", maxUAPIGetBytes+1)); err == nil {
		t.Fatal("an oversized UAPI response was read, want it refused")
	}
}

// The secret values a UAPI dump carries. They are distinctive so a leak into
// any output is found by substring.
var (
	secretPrivateHex   = strings.Repeat("5e", 32)
	secretPresharedHex = strings.Repeat("c7", 32)
)

// secretForms returns every encoding of the two secrets a leak could take.
func secretForms(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, h := range []string{secretPrivateHex, secretPresharedHex} {
		raw, err := hex.DecodeString(h)
		if err != nil {
			t.Fatalf("decode secret: %v", err)
		}
		out = append(out, h, strings.ToUpper(h), base64.StdEncoding.EncodeToString(raw))
	}
	return out
}

// TestHandshakeReadLeaksNoSecrets feeds a UAPI dump carrying a private_key and
// a preshared_key (and a malformed peer, so the skip path logs) through the
// device read, the mesh, and the status writer, and asserts neither secret
// appears in the parsed result, a status patch, or any log line.
func TestHandshakeReadLeaksNoSecrets(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	dev, wg, _ := applierDevice(t)
	dev.log = log
	m, err := New(netip.MustParsePrefix("100.64.0.0/24"), withDevice(dev), WithLogger(log))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	w, err := NewWatcher(&rest.Config{Host: "https://127.0.0.1:1"}, m, log, WithHandshakeStatus())
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	rec := &statusRecorder{}
	w.patchStatus = rec.patch
	seedPeer(t, w, "nodeB", "100.64.1.0/24", "192.0.2.2:51820", 0x42, "1")
	wg.get = fmt.Sprintf("private_key=%s\nlisten_port=51820\n"+
		"public_key=%s\npreshared_key=%s\nlast_handshake_time_sec=100\nlast_handshake_time_nsec=0\n"+
		"public_key=%s\nlast_handshake_time_sec=100\n"+
		"errno=0\n", secretPrivateHex, keyHex(t, 0x42), secretPresharedHex, secretPrivateHex[:10])

	parsed, skipped, err := ParseHandshakes(wg.get)
	if err != nil || skipped != 1 || len(parsed) != 1 {
		t.Fatalf("ParseHandshakes = %v, skipped %d, err %v; want one peer and one skipped", parsed, skipped, err)
	}
	w.resync(context.Background())
	if rec.count() != 1 {
		t.Fatalf("status patches = %v, want one for nodeB", rec.patches)
	}
	if !strings.Contains(logs.String(), "skipped=1") {
		t.Fatalf("the skipped peer was not logged; logs:\n%s", logs.String())
	}
	var surfaces []string
	for k, v := range parsed {
		surfaces = append(surfaces, k, v.String())
	}
	for _, ps := range rec.patches {
		surfaces = append(surfaces, ps...)
	}
	surfaces = append(surfaces, logs.String())
	all := strings.Join(surfaces, "\n")
	for _, secret := range secretForms(t) {
		if strings.Contains(all, secret) {
			t.Fatalf("secret %q leaked into the parsed result, a patch, or the logs:\n%s", secret, all)
		}
	}
}

// blockingReader is a Device whose handshake read blocks until released or
// its context ends, recording whether that context carried a deadline.
type blockingReader struct {
	fakeDevice
	entered     chan struct{}
	release     chan struct{}
	hadDeadline bool
}

func (b *blockingReader) PeerHandshakes(ctx context.Context) (map[string]time.Time, error) {
	_, b.hadDeadline = ctx.Deadline()
	close(b.entered)
	select {
	case <-b.release:
		return map[string]time.Time{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TestPeerHandshakesDoesNotHoldMeshLock pins that the handshake read (a netd
// round trip in helper mode) runs without the mesh's lock and under a
// deadline: while a reader blocks, the lock Reconcile and Close take is free.
func TestPeerHandshakesDoesNotHoldMeshLock(t *testing.T) {
	dev := &blockingReader{entered: make(chan struct{}), release: make(chan struct{})}
	m, err := New(netip.MustParsePrefix("100.64.0.0/24"), withDevice(dev), WithLogger(discardLogger()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := m.PeerHandshakes(context.Background())
		done <- err
	}()
	<-dev.entered
	if !m.mu.TryLock() {
		close(dev.release)
		t.Fatal("Mesh.PeerHandshakes holds the mesh lock across the device read")
	}
	m.mu.Unlock()
	close(dev.release)
	if err := <-done; err != nil {
		t.Fatalf("PeerHandshakes: %v", err)
	}
	if !dev.hadDeadline {
		t.Fatal("the device read ran with no deadline")
	}
}

// tooOldReader is a Device whose handshake read always reports an old helper.
type tooOldReader struct{ fakeDevice }

func (*tooOldReader) PeerHandshakes(context.Context) (map[string]time.Time, error) {
	return nil, fmt.Errorf("%w: test", wire.ErrHelperTooOld)
}

// TestWatcherLogsHelperTooOldOnce pins that an old netd helper is reported once,
// not on every resync pass.
func TestWatcherLogsHelperTooOldOnce(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	m, err := New(netip.MustParsePrefix("100.64.0.0/24"), withDevice(&tooOldReader{}), WithLogger(discardLogger()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	w, err := NewWatcher(&rest.Config{Host: "https://127.0.0.1:1"}, m, log, WithHandshakeStatus())
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	w.patchStatus = (&statusRecorder{}).patch
	seedPeer(t, w, "nodeB", "100.64.1.0/24", "192.0.2.2:51820", 0x42, "1")
	for range 3 {
		w.resync(context.Background())
	}
	if n := strings.Count(logs.String(), "helper is too old to report"); n != 1 {
		t.Fatalf("three passes against an old helper logged it %d times, want 1:\n%s", n, logs.String())
	}
}

// FuzzParseHandshakes checks the UAPI get parser on arbitrary input: it never
// panics, every key it returns is a lowercase 32-byte hex key that the input
// named on a public_key line, no returned time is zero, and it never returns
// more than maxParsedPeers peers. Seeds live in testdata/fuzz.
func FuzzParseHandshakes(f *testing.F) {
	f.Add("public_key=" + strings.Repeat("ab", 32) + "\nlast_handshake_time_sec=10\nlast_handshake_time_nsec=5\n")
	f.Fuzz(func(t *testing.T, in string) {
		got, skipped, err := ParseHandshakes(in)
		if err != nil {
			if len(in) <= maxUAPIGetBytes {
				t.Fatalf("ParseHandshakes failed on %d bytes: %v", len(in), err)
			}
			return
		}
		if skipped < 0 || len(got) > maxParsedPeers {
			t.Fatalf("ParseHandshakes returned %d peers, skipped %d", len(got), skipped)
		}
		lower := strings.ToLower(in)
		for k, v := range got {
			if raw, derr := hex.DecodeString(k); derr != nil || len(raw) != wgKeyBytes || k != strings.ToLower(k) {
				t.Fatalf("returned key %q is not a lowercase 32-byte hex key", k)
			}
			if !strings.Contains(lower, "public_key="+k) {
				t.Fatalf("returned key %q was not named on a public_key line", k)
			}
			if v.IsZero() || v.Equal(time.Unix(0, 0)) {
				t.Fatalf("returned a zero handshake time for %q", k)
			}
		}
	})
}

// TestPeerHandshakesNeedsAReader pins that a device that cannot report
// handshakes yields ErrNoHandshakeReader rather than an empty view.
func TestPeerHandshakesNeedsAReader(t *testing.T) {
	m, err := New(netip.MustParsePrefix("100.64.0.0/24"), withDevice(&fakeDevice{}), WithLogger(discardLogger()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := m.PeerHandshakes(context.Background()); !errors.Is(err, ErrNoHandshakeReader) {
		t.Fatalf("PeerHandshakes err = %v, want ErrNoHandshakeReader", err)
	}
}
