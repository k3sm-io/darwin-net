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
	"time"
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

// MaxApplyUpdateRequestBytes caps an ApplyUpdate request (the signed payload,
// its signature and the signer certificate). The daemon reads every frame under
// the larger of this and its configured request cap, then refuses any other verb
// whose frame exceeds the configured cap, so only ApplyUpdate gets the room.
const MaxApplyUpdateRequestBytes = 256 << 10

// DefaultMaxPerConn bounds the aliases, mesh routes, and bound ports a single
// connection may drive. It is ≈ a node's /24 pod capacity (253 usable hosts), so
// one connection's blast radius is capped at one node's worth of state.
const DefaultMaxPerConn = 253

// Protocol version. A peer with a different MAJOR cannot interoperate (the daemon
// rejects it); a higher MINOR is additive/compatible and is accepted. Minor 1
// added the direct-link verbs (ConfigureLink, RemoveLink) and ConfigureMeshArgs.DirectRoutes; they are withdrawn, and this daemon answers either verb "unknown
// verb", which a minor-1 client already treats as a mesh-only helper. Minor 2 adds
// Hello and the interconnect verbs (EnsureInterconnectAlias,
// RemoveInterconnectAlias) with Response.Reason and Response.InterconnectIP. Every
// reply carries the daemon's own version, and a client sends a newer verb only to
// a daemon that reported a minor that understands it: an older daemon does not
// decode strictly, so it would silently drop a field it does not know. Minor 3
// added ApplyUpdate with Response.Phase and Response.Log. Minor 4 replaces the
// ApplyUpdate request with a server-signed payload and the archive path
// (ApplyUpdateArgs); a minor-3 request shape is no longer accepted. Minor 5 adds
// the read-only MeshPeerStats verb with Response.MeshPeerStats.
const (
	ProtocolVersionMajor = 1
	ProtocolVersionMinor = 5
)

// MinorInterconnect is the first minor version that understands Hello and the
// interconnect alias verbs.
const MinorInterconnect = 2

// MinorApplyUpdate is the first minor version that understands the signed
// ApplyUpdate request. A minor-3 daemon speaks a withdrawn request shape, so a
// client treats it as too old for the verb.
const MinorApplyUpdate = 4

// MinorMeshPeerStats is the first minor version that understands MeshPeerStats.
const MinorMeshPeerStats = 5

// UpdateInstallTimeout bounds the one installer run ApplyUpdate makes. The
// daemon kills the installer's whole process group when it expires.
const UpdateInstallTimeout = 20 * time.Minute

// MaxUpdateSetBytes caps the bytes an ApplyUpdate archive may unpack to (2 GiB),
// counting the members the daemon reads past. A larger archive is refused while
// it is extracted.
const MaxUpdateSetBytes int64 = 2 << 30

// MaxUpdateArchiveBytes caps the release archive an ApplyUpdate names (512 MiB).
const MaxUpdateArchiveBytes int64 = 512 << 20

// MaxUpdateArchiveMembers caps the entries an ApplyUpdate archive may hold.
const MaxUpdateArchiveMembers = 4096

// UpdateSignerCommonName and UpdateSignerOrganization are the subject an
// ApplyUpdate signer certificate must carry, under the cluster CA, together
// with the Code Signing extended key usage.
const (
	UpdateSignerCommonName   = "k3sm:update-signer"
	UpdateSignerOrganization = "k3sm:update-signers"
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
	// ErrFlushedSocket means the daemon's handed-over socket arrived flushed
	// (SO_RCVBUF zero: the darwin unix-socket garbage collector ran on it in
	// flight) on every attempt the client makes; see Client.
	ErrFlushedSocket = errors.New("netd handed over a socket the kernel had flushed")
	// ErrHelperTooOld is returned, without anything sent, by a client method whose
	// verb the daemon on the current connection does not understand (it reported a
	// minor below the verb's).
	ErrHelperTooOld = errors.New("netd/wire: the netd helper is too old for this verb")
)

// The named interconnect refusals. The daemon wraps the matching one in every
// interconnect rejection and names it in Response.Reason; the client maps the
// reason back, so a caller compares with errors.Is across the socket.
var (
	// ErrInterconnectSlotOutOfRange: the slot is outside
	// 0..netv1alpha1.MaxInterconnectSlot.
	ErrInterconnectSlotOutOfRange = errors.New("netd: interconnect slot out of range")
	// ErrInterconnectIndexOutOfRange: the node's cluster index, derived from the
	// daemon's adopted node pod CIDR, is beyond
	// netv1alpha1.MaxInterconnectNodeIndex, so the node has no interconnect
	// address. The k3sm side reports it as InterconnectIndexOutOfRange.
	ErrInterconnectIndexOutOfRange = errors.New("netd: node cluster index out of the interconnect range")
	// ErrInterconnectIdentityUnadopted: the daemon has no adopted node pod CIDR
	// yet (no ConfigureMesh confirmed one and none was restored), so it has no
	// index to derive an address from.
	ErrInterconnectIdentityUnadopted = errors.New("netd: node identity not adopted yet")
	// ErrInterconnectNoBridge: the host has no bridge0 interface.
	ErrInterconnectNoBridge = errors.New("netd: bridge0 does not exist")
	// ErrInterconnectTeardownOrder: slot 0 (the connected /24) cannot be removed
	// while the daemon owns a slot 1..7 /32 alias that rides it.
	ErrInterconnectTeardownOrder = errors.New("netd: slot 0 is removed only after every slot 1..7 alias")
)

// Response.Reason values for the named interconnect refusals.
const (
	ReasonInterconnectSlotOutOfRange    = "InterconnectSlotOutOfRange"
	ReasonInterconnectIndexOutOfRange   = "InterconnectIndexOutOfRange"
	ReasonInterconnectIdentityUnadopted = "InterconnectIdentityUnadopted"
	ReasonInterconnectNoBridge          = "InterconnectNoBridge"
	ReasonInterconnectTeardownOrder     = "InterconnectTeardownOrder"
)

// reasons is the one table pairing each Reason with its sentinel.
var reasons = []struct {
	reason string
	err    error
}{
	{ReasonInterconnectSlotOutOfRange, ErrInterconnectSlotOutOfRange},
	{ReasonInterconnectIndexOutOfRange, ErrInterconnectIndexOutOfRange},
	{ReasonInterconnectIdentityUnadopted, ErrInterconnectIdentityUnadopted},
	{ReasonInterconnectNoBridge, ErrInterconnectNoBridge},
	{ReasonInterconnectTeardownOrder, ErrInterconnectTeardownOrder},
}

// ReasonOf returns the Response.Reason naming the first sentinel err wraps, or ""
// when it wraps none.
func ReasonOf(err error) string {
	for _, r := range reasons {
		if errors.Is(err, r.err) {
			return r.reason
		}
	}
	return ""
}

// errorOfReason returns the sentinel a Response.Reason names, or nil.
func errorOfReason(reason string) error {
	for _, r := range reasons {
		if r.reason == reason {
			return r.err
		}
	}
	return nil
}

// Version is the protocol version a Request advertises.
type Version struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}

// CurrentVersion is the version this build speaks.
func CurrentVersion() Version {
	return Version{Major: ProtocolVersionMajor, Minor: ProtocolVersionMinor}
}

// SupportsInterconnect reports whether a daemon reporting v understands Hello
// and the interconnect alias verbs.
func (v Version) SupportsInterconnect() bool {
	return v.Major == ProtocolVersionMajor && v.Minor >= MinorInterconnect
}

// SupportsApplyUpdate reports whether a daemon reporting v understands
// ApplyUpdate.
func (v Version) SupportsApplyUpdate() bool {
	return v.Major == ProtocolVersionMajor && v.Minor >= MinorApplyUpdate
}

// SupportsMeshPeerStats reports whether a daemon reporting v understands
// MeshPeerStats.
func (v Version) SupportsMeshPeerStats() bool {
	return v.Major == ProtocolVersionMajor && v.Minor >= MinorMeshPeerStats
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
	// VerbBindPort binds a listening socket and returns its fd via SCM_RIGHTS.
	VerbBindPort Verb = "BindPort"
	// VerbHello carries no arguments and changes nothing; the reply reports the
	// daemon's version. A client sends it first on a connection to learn what that
	// daemon understands before it sends a newer verb. A daemon older than minor 2
	// answers it "unknown verb", and that reply still carries its version. Minor 2.
	VerbHello Verb = "Hello"
	// VerbEnsureInterconnectAlias asks the daemon to put the interconnect address
	// of one slot on bridge0. The client sends only the slot; the daemon derives
	// the address itself, InterconnectSlotAddress(index of its adopted node pod
	// CIDR, slot), with a /24 netmask for slot 0 (the node's connected interconnect
	// subnet) and /32 for slots 1..7, and adds no route. The slot bound (0..7)
	// bounds bridge0 at 8 interconnect aliases per node. Minor 2.
	VerbEnsureInterconnectAlias Verb = "EnsureInterconnectAlias"
	// VerbRemoveInterconnectAlias removes one slot's interconnect alias from
	// bridge0, only when the daemon created or adopted it, and slot 0 only after
	// every slot 1..7 alias. The slot bound (0..7) bounds bridge0 at 8
	// interconnect aliases per node. Minor 2.
	VerbRemoveInterconnectAlias Verb = "RemoveInterconnectAlias"
	// VerbApplyUpdate installs a k3sm release the cluster's update signer
	// authorised. The request carries the signed payload, its signature, the
	// signer certificate and the path of the release archive the unprivileged
	// agent downloaded. The daemon verifies the certificate against the cluster
	// CA and the signature over the payload, hashes the archive against the
	// payload's sha256, extracts it itself into a fresh root-only directory,
	// applies the code-signing and downgrade policy, and only then runs the
	// staged k3sm's `install --from-staging`, the one binary of the set it ever
	// runs. The daemon never downloads anything. The reply is a stream of
	// frames, one per UpdatePhase, ending in Done or Failed; the client
	// acknowledges the Installing frame with a Hello request before the daemon
	// runs the installer (see UpdatePhaseInstalling). Minor 4.
	VerbApplyUpdate Verb = "ApplyUpdate"
	// VerbMeshPeerStats carries no arguments and changes nothing; the reply lists,
	// in Response.MeshPeerStats, the most recent wireguard handshake the daemon's
	// mesh device completed with each peer that has one. A daemon with no mesh
	// up answers with an empty list. Minor 5.
	VerbMeshPeerStats Verb = "MeshPeerStats"
)

// UpdatePhase names one step of an ApplyUpdate, as the daemon reports it.
type UpdatePhase string

// The ApplyUpdate phases, in the order they are reported.
const (
	// UpdatePhaseVerifying: the daemon is checking the signature, the archive
	// digest, the extracted set and its code signatures.
	UpdatePhaseVerifying UpdatePhase = "Verifying"
	// UpdatePhaseInstalling: every check passed and the installer is about to
	// run. The client acknowledges this frame with a Hello request on the same
	// connection; the daemon runs the installer once the ack arrives, or after
	// a short bound without it.
	UpdatePhaseInstalling UpdatePhase = "Installing"
	// UpdatePhaseRestarting is never sent by the daemon. The k3sm node writes
	// it early, on the Installing frame and before its acknowledgement, because
	// the installer stops the node's daemon. The client also reports it when
	// the stream ends after Installing with no final frame: the installer
	// restarts the daemon itself, which closes the connection mid-install. The
	// install continues in its own session; the restarted node's version is the
	// outcome.
	UpdatePhaseRestarting UpdatePhase = "Restarting"
	// UpdatePhaseDone: the installer exited 0.
	UpdatePhaseDone UpdatePhase = "Done"
	// UpdatePhaseFailed: the set was refused or the installer failed;
	// Response.Error says why and Response.Log carries the installer's last
	// lines when it ran.
	UpdatePhaseFailed UpdatePhase = "Failed"
)

// Terminal reports whether p ends an ApplyUpdate stream.
func (p UpdatePhase) Terminal() bool {
	return p == UpdatePhaseDone || p == UpdatePhaseFailed
}

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
// the node's own pod /24, and the typed peer set.
type ConfigureMeshArgs struct {
	LocalPrivKeyRef string `json:"localPrivKeyRef"`
	ListenPort      int    `json:"listenPort,omitempty"`
	// NodePodCIDR, when present, is the node's OWN pod /24 as the client knows it.
	// It exists because netd is started by the installer before the node joins, so
	// on a worker it boots with the server's /24 as its node identity and cannot be
	// restarted to learn the real one (a restart drops every alias and route on the
	// node). The daemon adopts it once, before anything is live, and refuses a later
	// change; see netd.Server's ConfigureMesh handling. The field is additive: an
	// older client omits it and the daemon keeps its configured identity.
	NodePodCIDR string        `json:"nodePodCIDR,omitempty"`
	Peers       []MeshPeerArg `json:"peers,omitempty"`
}

// InterconnectAliasArgs names one interconnect slot. It is the only argument
// the interconnect verbs carry: never an address, prefix, netmask, interface or
// route.
type InterconnectAliasArgs struct {
	Slot int `json:"slot"`
}

// ApplyUpdateArgs carries one managed update.
//
// ArchivePath is the absolute, clean path of the release archive (a gzip tar)
// the unprivileged agent downloaded: a regular file the service uid owns, at
// most MaxUpdateArchiveBytes. Payload is the canonical payload JSON exactly as
// the update controller wrote it on the Node
// ({"version","url","sha256","signature","allowDowngrade"}); the daemon takes
// the release tag, the archive digest, the code-signing policy and the
// downgrade permission from it and from nothing else. Signature is a
// DER-encoded ECDSA signature over the SHA-256 of Payload, and SignerCert the
// PEM certificate of the key that made it, which must chain to the cluster CA
// the daemon was started with, carry the Code Signing extended key usage, and
// name the subject UpdateSignerCommonName, UpdateSignerOrganization.
type ApplyUpdateArgs struct {
	ArchivePath string `json:"archivePath"`
	Payload     []byte `json:"payload"`
	Signature   []byte `json:"signature"`
	SignerCert  []byte `json:"signerCert"`
}

// BindPortArgs requests a listening socket on a node address and port. A specific
// address is the norm. A wildcard address is accepted only for a privileged
// (<1024) port and only when the daemon's port authorizer grants it; a wildcard on
// a port at or above 1024 is refused. Protocol defaults to "tcp".
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
	BindPort      *BindPortArgs      `json:"bindPort,omitempty"`

	EnsureInterconnectAlias *InterconnectAliasArgs `json:"ensureInterconnectAlias,omitempty"`
	RemoveInterconnectAlias *InterconnectAliasArgs `json:"removeInterconnectAlias,omitempty"`

	ApplyUpdate *ApplyUpdateArgs `json:"applyUpdate,omitempty"`
}

// Response is the daemon's reply. Version is the DAEMON's protocol version, on
// every reply, success or not, so a client learns what the daemon understands
// from any exchange. For VerbBindPort an fd accompanies the response out-of-band
// via SCM_RIGHTS when FDPassed is true. For the interconnect verbs,
// InterconnectIP is the address the daemon derived, and Reason names the refusal
// (one of the Reason* constants) when the rejection is a named one. For
// VerbApplyUpdate, Phase names the step each frame reports and Log, on the final
// frame, carries the installer's last lines.
type Response struct {
	Version        Version `json:"version"`
	OK             bool    `json:"ok"`
	Error          string  `json:"error,omitempty"`
	Reason         string  `json:"reason,omitempty"`
	FDPassed       bool    `json:"fdPassed,omitempty"`
	BoundAddr      string  `json:"boundAddr,omitempty"`
	InterconnectIP string  `json:"interconnectIP,omitempty"`

	Phase UpdatePhase `json:"phase,omitempty"`
	Log   string      `json:"log,omitempty"`

	MeshPeerStats []MeshPeerStat `json:"meshPeerStats,omitempty"`
}

// MeshPeerStat is one wireguard peer's handshake state in a MeshPeerStats reply.
type MeshPeerStat struct {
	// PubKey is the peer's wireguard public key, base64 (the MeshPeerArg form).
	PubKey string `json:"pubKey"`
	// LastHandshakeUnixNano is the peer's most recent completed handshake, in
	// nanoseconds since the Unix epoch. A peer with no handshake is not listed.
	LastHandshakeUnixNano int64 `json:"lastHandshakeUnixNano"`
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
