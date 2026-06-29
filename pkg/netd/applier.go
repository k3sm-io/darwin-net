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

package netd

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"

	"k3sm.io/darwin-net/pkg/mesh"
	"k3sm.io/darwin-net/pkg/podnet"
)

// Privileged is the root-only datapath the daemon drives AFTER it has
// authenticated the peer and validated + rendered a request. It is the seam
// between netd's pure policy core (peer-auth, CIDR/route/port validation, UAPI/pf
// rendering — all unit-tested) and the irreducibly-privileged darwin operations.
// NewServer uses the production darwin implementation when Config.Privileged is
// nil; tests (and an alternate host) inject their own. The server never lets an
// unvalidated parameter reach this interface.
type Privileged interface {
	// EnsureAlias plumbs ip as a /32 lo0 alias (idempotent).
	EnsureAlias(ctx context.Context, ip netip.Addr) error
	// RemoveAlias tears ip's /32 lo0 alias down (leak-free, idempotent).
	RemoveAlias(ctx context.Context, ip netip.Addr) error
	// ConfigureMesh brings the wireguard mesh up with privKeyB64 + listenPort (once)
	// and applies the already-validated, already-rendered plan.
	ConfigureMesh(ctx context.Context, privKeyB64 string, listenPort int, plan mesh.Plan) error
	// RemoveMesh tears the wireguard mesh down (leak-free, idempotent).
	RemoveMesh(ctx context.Context) error
	// LoadPFAnchor loads the utun-scoped MSS-clamp rule (mssClamp already validated).
	LoadPFAnchor(ctx context.Context, mssClamp int) error
	// BindPort binds a listening socket on the specific addr and returns it; the
	// caller passes the fd to the client and closes this copy.
	BindPort(ctx context.Context, network string, addr netip.AddrPort) (*os.File, error)
}

// darwinApplier is the production Privileged: it shells out to ifconfig/pfctl and
// binds sockets directly, and drives the real wireguard mesh device (pkg/mesh).
// It runs as root inside the daemon; unit tests inject a fake Privileged instead,
// so this code path is exercised only in the root-gated integration tier.
//
// Locking discipline: the lazily-built mesh device and its up/iface state are
// guarded by mu so concurrent ConfigureMesh/RemoveMesh/LoadPFAnchor calls (from
// different connections) serialize. Alias and port operations are independent
// (the kernel serializes them) and take no lock here.
type darwinApplier struct {
	nodePodCIDR netip.Prefix
	meshIP      netip.Addr // derived from nodePodCIDR; invalid if the CIDR is bad
	utunName    string
	log         *slog.Logger

	mu     sync.Mutex
	dev    *mesh.WGDevice
	meshUp bool
}

// newDarwinApplier builds the production executor for a node whose pod /24 is
// nodePodCIDR. The mesh-egress source is derived once; if nodePodCIDR is not a
// usable /24 the derivation fails and mesh operations return an error (alias/port
// operations are unaffected).
func newDarwinApplier(nodePodCIDR netip.Prefix, log *slog.Logger) *darwinApplier {
	if log == nil {
		log = slog.Default()
	}
	meshIP, _ := podnet.MeshEgressIP(nodePodCIDR)
	return &darwinApplier{
		nodePodCIDR: nodePodCIDR,
		meshIP:      meshIP,
		utunName:    "utun",
		log:         log,
	}
}

// EnsureAlias adds ip as a /32 alias on lo0.
func (a *darwinApplier) EnsureAlias(ctx context.Context, ip netip.Addr) error {
	if err := run(ctx, "ifconfig", "lo0", "alias", fmt.Sprintf("%s/32", ip)); err != nil {
		return fmt.Errorf("ifconfig lo0 alias %s/32: %w", ip, err)
	}
	return nil
}

// RemoveAlias removes ip's lo0 alias. An absent alias is tolerated (leak-free
// teardown), so the error is logged, not returned.
func (a *darwinApplier) RemoveAlias(ctx context.Context, ip netip.Addr) error {
	if err := run(ctx, "ifconfig", "lo0", "-alias", ip.String()); err != nil {
		a.log.Debug("ifconfig lo0 -alias tolerated (address may be absent)", "ip", ip.String(), "err", err)
	}
	return nil
}

// ConfigureMesh builds (once) and brings up the real wireguard device with the
// resolved private key and listen port, then applies the validated plan.
func (a *darwinApplier) ConfigureMesh(ctx context.Context, privKeyB64 string, listenPort int, plan mesh.Plan) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dev == nil {
		if !a.meshIP.IsValid() {
			return fmt.Errorf("configure mesh: node podCIDR %s has no mesh-egress source", a.nodePodCIDR)
		}
		a.dev = mesh.NewDevice(mesh.DeviceConfig{
			UTUNName:      a.utunName,
			MeshIP:        a.meshIP,
			PrivateKeyB64: privKeyB64,
			ListenPort:    listenPort,
		}, a.log)
	}
	if !a.meshUp {
		if err := a.dev.Up(ctx); err != nil {
			return fmt.Errorf("mesh up: %w", err)
		}
		a.meshUp = true
	}
	if err := a.dev.Apply(ctx, plan); err != nil {
		return fmt.Errorf("apply mesh plan: %w", err)
	}
	return nil
}

// RemoveMesh tears the wireguard mesh down.
func (a *darwinApplier) RemoveMesh(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dev == nil || !a.meshUp {
		return nil
	}
	if err := a.dev.Down(ctx); err != nil {
		return fmt.Errorf("mesh down: %w", err)
	}
	a.meshUp = false
	return nil
}

// LoadPFAnchor loads the MSS-clamp rule scoped to the live mesh utun. It requires
// the mesh to be up (the clamp is meaningless without a utun to scope it to); the
// rule text is rendered here from the validated clamp, never accepted over the wire.
func (a *darwinApplier) LoadPFAnchor(ctx context.Context, mssClamp int) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dev == nil || !a.meshUp {
		return fmt.Errorf("load pf anchor: mesh not configured (no utun to scope the MSS clamp)")
	}
	iface := a.dev.Interface()
	if iface == "" {
		return fmt.Errorf("load pf anchor: mesh utun not resolved")
	}
	cmd := exec.CommandContext(ctx, "pfctl", "-a", mesh.PFAnchor, "-f", "-")
	cmd.Stdin = bytes.NewBufferString(mesh.PFMSSClampRule(iface, mssClamp))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl load %s: %w: %s", mesh.PFAnchor, err, bytes.TrimSpace(out))
	}
	return nil
}

// BindPort binds a listening socket on addr and returns it as an *os.File so the
// server can pass the descriptor to the client over SCM_RIGHTS. The original
// listener is closed after the descriptor is duplicated; the kernel keeps the
// socket alive while the passed descriptor is open.
func (a *darwinApplier) BindPort(_ context.Context, network string, addr netip.AddrPort) (*os.File, error) {
	switch network {
	case "tcp":
		ln, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(addr))
		if err != nil {
			return nil, fmt.Errorf("listen tcp %s: %w", addr, err)
		}
		f, err := ln.File()
		_ = ln.Close()
		if err != nil {
			return nil, fmt.Errorf("dup tcp socket %s: %w", addr, err)
		}
		return f, nil
	case "udp":
		c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr))
		if err != nil {
			return nil, fmt.Errorf("listen udp %s: %w", addr, err)
		}
		f, err := c.File()
		_ = c.Close()
		if err != nil {
			return nil, fmt.Errorf("dup udp socket %s: %w", addr, err)
		}
		return f, nil
	default:
		return nil, fmt.Errorf("bind port: unsupported network %q", network)
	}
}

// run invokes a root-gated command, wrapping any failure with its combined output.
func run(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}
