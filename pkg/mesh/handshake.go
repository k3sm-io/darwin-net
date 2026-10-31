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
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
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

// ParseHandshakes reads the per-peer handshake times out of a wireguard UAPI
// get response (wireguard-go's IpcGet output): every public_key= line opens a
// peer, and its last_handshake_time_sec= and last_handshake_time_nsec= lines
// give the time. A peer whose time is zero (never) is left out. The result is
// keyed by the hex public key.
func ParseHandshakes(uapi string) (map[string]time.Time, error) {
	out := make(map[string]time.Time)
	var key string
	var sec, nsec int64
	flush := func() {
		if key != "" && (sec != 0 || nsec != 0) {
			out[key] = time.Unix(sec, nsec).UTC()
		}
		key, sec, nsec = "", 0, 0
	}
	sc := bufio.NewScanner(strings.NewReader(uapi))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		var err error
		switch k {
		case "public_key":
			flush()
			if _, derr := hex.DecodeString(v); derr != nil || len(v) != 64 {
				return nil, fmt.Errorf("parse wireguard peer public key %q: not a 32-byte hex key", v)
			}
			key = v
		case "last_handshake_time_sec":
			sec, err = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, err = strconv.ParseInt(v, 10, 64)
		}
		if err != nil {
			return nil, fmt.Errorf("parse wireguard %s=%q: %w", k, v, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read wireguard UAPI get response: %w", err)
	}
	flush()
	return out, nil
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
	return ParseHandshakes(uapi)
}

// PeerHandshakes asks the netd daemon for its mesh device's per-peer handshake
// times (the read-only MeshPeerStats verb) and re-keys them by hex public key.
func (d *netdDevice) PeerHandshakes(ctx context.Context) (map[string]time.Time, error) {
	stats, err := d.client.MeshPeerStats(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]time.Time, len(stats))
	for _, st := range stats {
		raw, err := base64.StdEncoding.DecodeString(st.PubKey)
		if err != nil {
			return nil, fmt.Errorf("decode netd peer public key %q: %w", st.PubKey, err)
		}
		out[hex.EncodeToString(raw)] = time.Unix(0, st.LastHandshakeUnixNano).UTC()
	}
	return out, nil
}

// PeerHandshakes returns this node's own view of the most recent wireguard
// handshake with each peer of the last applied plan, keyed by the peer's node
// name. A peer with no completed handshake is absent. It returns an error
// wrapping ErrNoHandshakeReader when the device cannot report handshakes.
func (m *Mesh) PeerHandshakes(ctx context.Context) (map[string]time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.dev.(handshakeReader)
	if !ok {
		return nil, fmt.Errorf("%w: %T", ErrNoHandshakeReader, m.dev)
	}
	byKey, err := r.PeerHandshakes(ctx)
	if err != nil {
		return nil, fmt.Errorf("read peer handshakes: %w", err)
	}
	out := make(map[string]time.Time, len(m.applied.Peers))
	for _, p := range m.applied.Peers {
		if t, ok := byKey[strings.ToLower(p.PublicKeyHex)]; ok {
			out[p.NodeName] = t
		}
	}
	return out, nil
}
