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
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	netv1 "k3sm.io/apis/net/v1"
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
// out, nanoseconds are kept, and a malformed key or number fails the read.
func TestParseHandshakes(t *testing.T) {
	k := keyHex(t, 0x42)
	got, err := ParseHandshakes(fmt.Sprintf("public_key=%s\nlast_handshake_time_sec=10\nlast_handshake_time_nsec=7\n", k))
	if err != nil {
		t.Fatalf("ParseHandshakes: %v", err)
	}
	if want := time.Unix(10, 7).UTC(); !got[k].Equal(want) || len(got) != 1 {
		t.Fatalf("ParseHandshakes = %v, want %s for %s", got, want, k)
	}
	for _, bad := range []string{
		"public_key=zz\n",
		fmt.Sprintf("public_key=%s\nlast_handshake_time_sec=x\n", k),
	} {
		if _, err := ParseHandshakes(bad); err == nil {
			t.Errorf("ParseHandshakes(%q) succeeded, want an error", bad)
		}
	}
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
