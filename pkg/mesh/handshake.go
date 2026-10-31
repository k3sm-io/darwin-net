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
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"k3sm.io/darwin-net/pkg/netd/wire"
)

// handshakeReader is the optional Device capability the Mesh reads per-peer
// handshake times through. It is a separate interface, not a Device method, so
// a device that cannot report them (a test fake, a future backend) still
// satisfies Device; Mesh.PeerHandshakes returns ErrNoHandshakeReader for it.
type handshakeReader interface {
	// PeerHandshakes returns the most recent completed wireguard handshake per
	// peer, keyed by the peer's hex public key (the UAPI form PeerConfig
	// carries). A peer that has never completed one is absent.
	PeerHandshakes(ctx context.Context) (map[string]time.Time, error)
}

// maxUAPIGetBytes caps the UAPI get response ParseHandshakes reads. A response
// for maxParsedPeers peers is a few tens of KiB; 1 MiB is a bound, not a budget.
const maxUAPIGetBytes = 1 << 20

// maxParsedPeers caps the peers ParseHandshakes returns: one node's worth of
// per-connection state on the netd side (wire.DefaultMaxPerConn), far beyond
// any real cluster.
const maxParsedPeers = wire.DefaultMaxPerConn

// handshakeReadTimeout bounds one per-peer handshake read, the netd round trip
// included, so a wedged helper cannot hold a reconcile pass open.
const handshakeReadTimeout = 5 * time.Second

// ParseHandshakes reads the per-peer handshake times out of a wireguard UAPI
// get response (wireguard-go's IpcGet output): every public_key= line opens a
// peer, and its last_handshake_time_sec= and last_handshake_time_nsec= lines
// give the time. A peer whose time is zero (never) is left out. The result is
// keyed by the lowercase hex public key.
//
// It fails closed per peer, never for the whole read: a peer whose public key
// is not 32 bytes of hex, or whose time is not a valid non-negative number, is
// dropped and counted in skipped, as is every peer past maxParsedPeers, and the
// rest are returned. Only the keys it recognises are read; every other line
// (private_key, preshared_key, endpoint, ...) is ignored, and no value from the
// input is ever echoed in an error. A response larger than maxUAPIGetBytes is
// refused whole.
func ParseHandshakes(uapi string) (handshakes map[string]time.Time, skipped int, err error) {
	if len(uapi) > maxUAPIGetBytes {
		return nil, 0, fmt.Errorf("wireguard UAPI get response is %d bytes, more than the %d allowed", len(uapi), maxUAPIGetBytes)
	}
	out := make(map[string]time.Time)
	var (
		key       string
		open, bad bool
		sec, nsec int64
	)
	flush := func() {
		switch {
		case !open:
		case bad:
			skipped++
		case sec == 0 && nsec == 0:
		case len(out) >= maxParsedPeers:
			skipped++
		default:
			out[key] = time.Unix(sec, nsec).UTC()
		}
		key, open, bad, sec, nsec = "", false, false, 0, 0
	}
	for line := range strings.Lines(uapi) {
		k, v, ok := strings.Cut(strings.TrimRight(line, "\r\n"), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			open = true
			if raw, derr := hex.DecodeString(v); derr != nil || len(raw) != wgKeyBytes {
				bad = true
				continue
			}
			key = strings.ToLower(v)
		case "last_handshake_time_sec":
			n, perr := strconv.ParseInt(v, 10, 64)
			if perr != nil || n < 0 {
				bad = true
			}
			sec = n
		case "last_handshake_time_nsec":
			n, perr := strconv.ParseInt(v, 10, 64)
			if perr != nil || n < 0 || n >= int64(time.Second) {
				bad = true
			}
			nsec = n
		}
	}
	flush()
	return out, skipped, nil
}

// PeerHandshakes reads the device's per-peer handshake times (wireguard's UAPI
// get). It returns an error when the device is not up.
func (d *WGDevice) PeerHandshakes(context.Context) (map[string]time.Time, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dev == nil {
		return nil, fmt.Errorf("%w: mesh device not up", ErrPeerConfig)
	}
	uapi, err := d.dev.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("read wireguard peers: %w", err)
	}
	out, skipped, err := ParseHandshakes(uapi)
	if err != nil {
		return nil, err
	}
	if skipped > 0 {
		d.log.Warn("wireguard peers skipped while reading handshakes", "skipped", skipped, "read", len(out))
	}
	return out, nil
}

// PeerHandshakes asks the netd daemon for its mesh device's per-peer handshake
// times (the read-only MeshPeerStats verb) and re-keys them by hex public key.
// As ParseHandshakes does on the in-process path, an entry whose key is not 32
// bytes of base64 is skipped, not fatal: the other peers are still returned and
// only the number skipped is logged, never a value from the entry.
func (d *netdDevice) PeerHandshakes(ctx context.Context) (map[string]time.Time, error) {
	stats, err := d.client.MeshPeerStats(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]time.Time, len(stats))
	skipped := 0
	for _, st := range stats {
		raw, err := base64.StdEncoding.DecodeString(st.PubKey)
		if err != nil || len(raw) != wgKeyBytes {
			skipped++
			continue
		}
		out[hex.EncodeToString(raw)] = time.Unix(0, st.LastHandshakeUnixNano).UTC()
	}
	if skipped > 0 {
		d.log.Warn("netd peer stats skipped while reading handshakes", "skipped", skipped, "read", len(out))
	}
	return out, nil
}

// PeerHandshakes returns this node's own view of the most recent wireguard
// handshake with each peer of the last applied plan, keyed by the peer's node
// name. A peer with no completed handshake is absent. It returns an error
// wrapping ErrNoHandshakeReader when the device cannot report handshakes.
//
// It holds mu only to snapshot the reader and the key-to-node map; the read
// itself (a netd round trip in helper mode) runs unlocked, under
// handshakeReadTimeout, so a slow helper never blocks Reconcile or Close.
func (m *Mesh) PeerHandshakes(ctx context.Context) (map[string]time.Time, error) {
	m.mu.Lock()
	r, ok := m.dev.(handshakeReader)
	nodeByKey := make(map[string]string, len(m.applied.Peers))
	for _, p := range m.applied.Peers {
		nodeByKey[strings.ToLower(p.PublicKeyHex)] = p.NodeName
	}
	dev := m.dev
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: %T", ErrNoHandshakeReader, dev)
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeReadTimeout)
	defer cancel()
	byKey, err := r.PeerHandshakes(ctx)
	if err != nil {
		return nil, fmt.Errorf("read peer handshakes: %w", err)
	}
	out := make(map[string]time.Time, len(nodeByKey))
	for key, node := range nodeByKey {
		if t, ok := byKey[key]; ok {
			out[node] = t
		}
	}
	return out, nil
}
