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
	"log/slog"
	"net/netip"

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
	self       netip.Prefix
	log        *slog.Logger
}

// newNetdDevice constructs a helper-backed Device dialing socketPath. privKeyRef
// is the opaque reference the daemon resolves to the node's private key root-side;
// self is the node's own pod /24, which every ConfigureMesh carries so a daemon
// still holding its pre-join default can adopt the node's real identity.
func newNetdDevice(socketPath, privKeyRef string, listenPort int, self netip.Prefix, log *slog.Logger) *netdDevice {
	if log == nil {
		log = slog.Default()
	}
	return &netdDevice{
		client:     wire.NewClient(socketPath),
		privKeyRef: privKeyRef,
		listenPort: listenPort,
		self:       self,
		log:        log,
	}
}

// Up brings the mesh tunnel up via the daemon with no peers yet (the daemon
// creates the utun, sets the resolved private key + listen port, and loads the
// MSS-clamp anchor). It is idempotent: the daemon's ConfigureMesh is.
func (d *netdDevice) Up(ctx context.Context) error {
	return d.client.ConfigureMesh(ctx, d.privKeyRef, d.listenPort, d.self, nil)
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
	return d.client.ConfigureMesh(ctx, d.privKeyRef, d.listenPort, d.self, peers)
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
