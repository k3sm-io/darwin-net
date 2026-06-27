package mesh

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"

	"k3sm.io/darwin-net/pkg/netd/wire"
)

// netdDevice is the helper-backed Device: instead of creating a utun and driving
// wireguard itself, it sends the typed peer set to the root netd daemon over a
// unix socket and the daemon renders the UAPI, installs the routes, and loads the
// MSS-clamp anchor. It lets an unprivileged process run the mesh controller while
// the irreducibly-root datapath stays behind the daemon boundary.
//
// It satisfies Device. The daemon's ConfigureMesh is the combined bring-up + apply
// (it creates the utun and sets the key on first call, then programs peers), so Up
// sends an empty-peer ConfigureMesh and Apply sends the rendered peer set. The
// private key never crosses the socket — only privKeyRef does, which the daemon
// resolves root-side.
type netdDevice struct {
	client     *wire.Client
	privKeyRef string
	listenPort int
	log        *slog.Logger
}

// newNetdDevice constructs a helper-backed Device dialing socketPath. privKeyRef
// is the opaque reference the daemon resolves to the node's private key root-side.
func newNetdDevice(socketPath, privKeyRef string, listenPort int, log *slog.Logger) *netdDevice {
	if log == nil {
		log = slog.Default()
	}
	return &netdDevice{
		client:     wire.NewClient(socketPath),
		privKeyRef: privKeyRef,
		listenPort: listenPort,
		log:        log,
	}
}

// Up brings the mesh tunnel up via the daemon with no peers yet (the daemon
// creates the utun, sets the resolved private key + listen port, and loads the
// MSS-clamp anchor). It is idempotent: the daemon's ConfigureMesh is.
func (d *netdDevice) Up(ctx context.Context) error {
	return d.client.ConfigureMesh(ctx, d.privKeyRef, d.listenPort, nil)
}

// Apply sends the plan's peer set to the daemon as typed scalars; the daemon
// re-validates and re-renders the UAPI + routes from them (it never accepts the
// rendered text). plan.Routes/plan.UAPI are recomputed daemon-side and so are not
// transmitted.
func (d *netdDevice) Apply(ctx context.Context, plan Plan) error {
	peers := make([]wire.MeshPeerArg, 0, len(plan.Peers))
	for _, pc := range plan.Peers {
		pub, err := hexToBase64(pc.PublicKeyHex)
		if err != nil {
			return fmt.Errorf("mesh peer %q: %w", pc.NodeName, err)
		}
		allowed := make([]string, len(pc.AllowedIPs))
		for i, a := range pc.AllowedIPs {
			allowed[i] = a.String()
		}
		peers = append(peers, wire.MeshPeerArg{PubKey: pub, Endpoint: pc.Endpoint, AllowedIPs: allowed})
	}
	return d.client.ConfigureMesh(ctx, d.privKeyRef, d.listenPort, peers)
}

// Down tears the mesh down via the daemon.
func (d *netdDevice) Down(ctx context.Context) error {
	return d.client.RemoveMesh(ctx)
}

// hexToBase64 re-encodes a hex wireguard key (the UAPI form a PeerConfig carries)
// into the base64 form the wire MeshPeerArg uses, so the daemon decodes it with
// the same wgKeyHex path a MeshPeerSpec takes.
func hexToBase64(h string) (string, error) {
	raw, err := hex.DecodeString(h)
	if err != nil {
		return "", fmt.Errorf("decode hex wireguard key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}
