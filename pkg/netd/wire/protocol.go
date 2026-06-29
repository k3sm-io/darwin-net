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

package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// DefaultSocketPath is the unix socket the k3sm-netd daemon listens on and the
// clients dial. It lives under the root-owned k3sm runtime dir so only root (the
// daemon) can create it and the directory permissions gate who may connect; the
// daemon additionally peer-authenticates every connection by uid.
const DefaultSocketPath = "/var/lib/k3sm/run/netd.sock"

// DefaultMaxRequestBytes caps a single framed message (request or response). It
// bounds the decoder's allocation so a malformed or hostile length prefix cannot
// exhaust memory. 64 KiB comfortably holds a whole-cluster mesh peer snapshot of
// typed scalars.
const DefaultMaxRequestBytes = 1 << 16

// DefaultMaxPerConn bounds the aliases, mesh routes, and bound ports a single
// connection may drive. It is ≈ a node's /24 pod capacity (253 usable hosts), so
// one connection's blast radius is capped at one node's worth of state.
const DefaultMaxPerConn = 253

// Protocol version. A peer with a different MAJOR cannot interoperate (the daemon
// rejects it); a higher MINOR is additive/compatible and is accepted.
const (
	ProtocolVersionMajor = 1
	ProtocolVersionMinor = 0
)

// Sentinel errors. Compare with errors.Is, never by string match.
var (
	// ErrFrameTooLarge is returned by ReadFrame when the length prefix exceeds the
	// caller's cap (the allocation bound).
	ErrFrameTooLarge = errors.New("netd/wire: frame exceeds max size")
	// ErrEmptyFrame is returned by ReadFrame for a zero-length frame (a desynced or
	// malformed stream).
	ErrEmptyFrame = errors.New("netd/wire: empty frame")
	// ErrNoFD is returned by the fd-receiving client path when the daemon's response
	// carried no file descriptor.
	ErrNoFD = errors.New("netd/wire: response carried no file descriptor")
)

// Version is the protocol version a Request advertises.
type Version struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}

// CurrentVersion is the version this build speaks.
func CurrentVersion() Version {
	return Version{Major: ProtocolVersionMajor, Minor: ProtocolVersionMinor}
}

// Compatible reports whether a peer speaking v can interoperate with this build:
// the MAJOR must match (an incompatible-major skew is rejected); any MINOR is
// accepted because minor revisions are additive/compatible.
func (v Version) Compatible() bool {
	return v.Major == ProtocolVersionMajor
}

// Verb names one operation in the closed RPC verb set.
type Verb string

// The closed verb set. Each verb carries only typed scalars (never route/pf/UAPI
// text); the daemon re-validates and renders the privileged artifacts itself.
const (
	// VerbEnsureAlias plumbs a /32 lo0 alias for a pod IP or Service VIP.
	VerbEnsureAlias Verb = "EnsureAlias"
	// VerbRemoveAlias tears a /32 lo0 alias down.
	VerbRemoveAlias Verb = "RemoveAlias"
	// VerbConfigureMesh brings the wireguard mesh up and programs its typed peers.
	VerbConfigureMesh Verb = "ConfigureMesh"
	// VerbRemoveMesh tears the wireguard mesh down.
	VerbRemoveMesh Verb = "RemoveMesh"
	// VerbLoadPFAnchor loads the utun-scoped MSS-clamp pf anchor.
	VerbLoadPFAnchor Verb = "LoadPFAnchor"
	// VerbBindPort binds a listening socket and returns its fd via SCM_RIGHTS.
	VerbBindPort Verb = "BindPort"
)

// EnsureAliasArgs carries the host IP to alias on lo0 as a /32 (no prefix text —
// the daemon appends /32 after validating containment).
type EnsureAliasArgs struct {
	IP string `json:"ip"`
}

// RemoveAliasArgs carries the host IP whose /32 lo0 alias to remove.
type RemoveAliasArgs struct {
	IP string `json:"ip"`
}

// MeshPeerArg is one typed wireguard peer: its PUBLIC key (base64), reachable
// endpoint, and AllowedIPs (each the peer's pod /24). It carries no private
// material and no rendered UAPI text — the daemon renders the UAPI itself.
type MeshPeerArg struct {
	PubKey     string   `json:"pubKey"`
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowedIPs"`
}

// ConfigureMeshArgs programs the mesh: a reference the daemon resolves to the
// node's PRIVATE key root-side (never the key itself), the wireguard listen port,
// and the typed peer set.
type ConfigureMeshArgs struct {
	LocalPrivKeyRef string        `json:"localPrivKeyRef"`
	ListenPort      int           `json:"listenPort,omitempty"`
	Peers           []MeshPeerArg `json:"peers,omitempty"`
}

// LoadPFAnchorArgs carries the TCP MSS the daemon clamps to on the mesh utun.
type LoadPFAnchorArgs struct {
	MSSClamp int `json:"mssClamp"`
}

// BindPortArgs requests a listening socket on a SPECIFIC node address (never the
// wildcard) and port. Protocol defaults to "tcp".
type BindPortArgs struct {
	Port     int    `json:"port"`
	NodeAddr string `json:"nodeAddr"`
	Protocol string `json:"protocol,omitempty"`
}

// Request is one framed RPC. Exactly one of the verb-specific arg pointers is set,
// matching Verb (RemoveMesh carries none).
type Request struct {
	Version       Version            `json:"version"`
	Verb          Verb               `json:"verb"`
	EnsureAlias   *EnsureAliasArgs   `json:"ensureAlias,omitempty"`
	RemoveAlias   *RemoveAliasArgs   `json:"removeAlias,omitempty"`
	ConfigureMesh *ConfigureMeshArgs `json:"configureMesh,omitempty"`
	LoadPFAnchor  *LoadPFAnchorArgs  `json:"loadPFAnchor,omitempty"`
	BindPort      *BindPortArgs      `json:"bindPort,omitempty"`
}

// Response is the daemon's reply. For VerbBindPort an fd accompanies the response
// out-of-band via SCM_RIGHTS when FDPassed is true.
type Response struct {
	Version   Version `json:"version"`
	OK        bool    `json:"ok"`
	Error     string  `json:"error,omitempty"`
	FDPassed  bool    `json:"fdPassed,omitempty"`
	BoundAddr string  `json:"boundAddr,omitempty"`
}

// Frame returns payload prefixed with its 4-byte big-endian length. It is the
// on-wire encoding both WriteFrame and the SCM_RIGHTS fd-send path use, so the
// receiver parses one format regardless of how the bytes arrived.
func Frame(payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out[:4], uint32(len(payload)))
	copy(out[4:], payload)
	return out
}

// WriteFrame writes payload to w with a 4-byte big-endian length prefix.
func WriteFrame(w io.Writer, payload []byte) error {
	if _, err := w.Write(Frame(payload)); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

// ReadFrame reads one length-prefixed frame from r, refusing a frame larger than
// max so a hostile length cannot drive an unbounded allocation. It returns
// ErrFrameTooLarge / ErrEmptyFrame for a malformed prefix and never panics.
func ReadFrame(r io.Reader, max int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, ErrEmptyFrame
	}
	if int64(n) > int64(max) {
		return nil, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, n, max)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(io.LimitReader(r, int64(n)), buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ParseFrame extracts the payload from framed bytes b (a 4-byte length prefix
// followed by the payload), as received in one SCM_RIGHTS datagram alongside an
// fd. It returns an error (never panics) when b is too short or truncated.
func ParseFrame(b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("%w: %d bytes", ErrEmptyFrame, len(b))
	}
	n := binary.BigEndian.Uint32(b[:4])
	if n == 0 {
		return nil, ErrEmptyFrame
	}
	if int64(n) > int64(len(b)-4) {
		return nil, fmt.Errorf("%w: frame says %d, have %d", io.ErrUnexpectedEOF, n, len(b)-4)
	}
	return b[4 : 4+n], nil
}
