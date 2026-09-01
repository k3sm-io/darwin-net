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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/mesh"
	"k3sm.io/darwin-net/pkg/netd/wire"
	"k3sm.io/darwin-net/pkg/podnet"
)

// DefaultSocketPath is the unix socket the daemon listens on (re-exported from the
// wire contract so callers can reference it as netd.DefaultSocketPath).
const DefaultSocketPath = wire.DefaultSocketPath

// DefaultIdleTimeout bounds how long an authenticated connection may sit between
// frames before the daemon reaps it. A unix-socket read blocks forever, so a peer
// that dies without closing its end (a crashed client, a wedged VM, a forwarded
// socket whose far side vanished) would otherwise pin a handler goroutine — and
// its per-connection accounting — for the lifetime of the daemon. Two minutes is
// far longer than any legitimate pause: the wire client dials a fresh connection
// per RPC and arms a 10s deadline on it (wire.defaultRPCTimeout), so nothing that
// is still alive waits this long between frames.
const DefaultIdleTimeout = 2 * time.Minute

// minMSSClamp is the smallest TCP MSS the daemon will load into the clamp anchor.
// A clamp below this is nonsensical (smaller than the headers leave room for) and
// is rejected; the ceiling is the mesh link's own max MSS.
const minMSSClamp = 216

// ErrPolicy is the base error a request that violates daemon policy wraps. It is
// surfaced to the client in the response Error string.
var ErrPolicy = errors.New("netd: request denied by policy")

// PortAuthorizer confirms a privileged (<1024) bind against an authoritative
// Service set: the daemon does not trust the client to self-assert that a real
// Service declares the port. It is a consumer seam (k3sm, which holds the Service
// informer, supplies it). A nil authorizer denies every <1024 bind (fail safe).
type PortAuthorizer interface {
	// Authorize returns a non-nil error to reject binding port on nodeAddr.
	Authorize(ctx context.Context, port int, nodeAddr string) error
}

// MeshKeyResolver resolves the opaque ConfigureMesh reference to the node's
// wireguard PRIVATE key (base64), root-side. The key never crosses the socket; the
// daemon resolves the ref here (e.g. a root-only key path or keyring handle). A nil
// resolver makes ConfigureMesh fail fast — there is no embedded-key default.
type MeshKeyResolver interface {
	// Resolve returns the base64 private key for ref, or an error.
	Resolve(ctx context.Context, ref string) (privKeyB64 string, err error)
}

// Config configures a Server. The CIDR aggregate, node podCIDR, and service uid
// are the policy inputs; the interface fields are seams with safe defaults (a uid
// PeerVerifier, the production darwin Privileged executor) or fail-safe behavior
// (a nil PortAuthorizer denies every <1024 bind; a nil MeshKeyResolver fails
// ConfigureMesh).
type Config struct {
	// ClusterAggregate is the pinned pod aggregate a pod alias must fall within
	// (default podnet.ClusterPodCIDR, 100.64.0.0/10).
	ClusterAggregate netip.Prefix
	// NodePodCIDR is this node's pod /24; a pod alias must fall within it.
	NodePodCIDR netip.Prefix
	// ServiceCIDR, when valid, additionally admits an EnsureAlias for a Service VIP
	// (the proxy's ClusterIPs live here, outside the pod aggregate). Optional.
	ServiceCIDR netip.Prefix
	// ServiceUID is the authorized unprivileged service uid (the default
	// PeerVerifier admits only this peer uid).
	ServiceUID uint32
	// MaxRequestBytes caps a single framed request (default DefaultMaxRequestBytes).
	MaxRequestBytes int
	// MaxPerConn caps the live aliases / mesh routes / bound ports one connection
	// may drive (default DefaultMaxPerConn, ≈ a node's /24 pod capacity).
	MaxPerConn int
	// IdleTimeout caps the gap between two frames on one connection before the
	// daemon reaps it (default DefaultIdleTimeout). It bounds the goroutine and
	// accounting a dead-but-unclosed peer can hold.
	IdleTimeout time.Duration

	// PortAuthorizer confirms a <1024 bind; nil denies every <1024 bind.
	PortAuthorizer PortAuthorizer
	// PeerVerifier authenticates each connection; nil uses the uid verifier
	// (ServiceUID).
	PeerVerifier PeerVerifier
	// MeshKeyResolver resolves the ConfigureMesh key ref; nil fails ConfigureMesh.
	MeshKeyResolver MeshKeyResolver
	// Privileged is the root-only executor; nil uses the production darwin executor.
	Privileged Privileged
	// Logger is the structured logger; nil uses slog.Default.
	Logger *slog.Logger
}

// Server is the k3sm-netd daemon logic: it accepts unix-socket connections,
// authenticates each peer, decodes the framed RPC, re-validates every parameter,
// renders the privileged artifacts, and applies them via the Privileged executor.
// It holds no per-request mutable state of its own (config is read-only after
// NewServer); per-connection accounting lives in connState.
type Server struct {
	cfg  Config
	log  *slog.Logger
	peer PeerVerifier
	priv Privileged
}

// NewServer constructs a Server from cfg, filling defaults: the cluster aggregate
// (podnet.ClusterPodCIDR), the request cap and per-connection cap, the uid
// PeerVerifier (ServiceUID), and the production darwin Privileged executor. It
// performs no I/O; call Serve to start accepting.
func NewServer(cfg Config) *Server {
	if !cfg.ClusterAggregate.IsValid() {
		cfg.ClusterAggregate = podnet.ClusterPodCIDR
	}
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = wire.DefaultMaxRequestBytes
	}
	if cfg.MaxPerConn <= 0 {
		cfg.MaxPerConn = wire.DefaultMaxPerConn
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	peer := cfg.PeerVerifier
	if peer == nil {
		peer = newUIDVerifier(cfg.ServiceUID)
	}
	priv := cfg.Privileged
	if priv == nil {
		priv = newDarwinApplier(cfg.NodePodCIDR, cfg.Logger)
	}
	return &Server{cfg: cfg, log: cfg.Logger, peer: peer, priv: priv}
}

// Serve accepts connections on l until ctx is cancelled, handling each in its own
// goroutine. It closes l on cancellation (which unblocks Accept) and waits for
// in-flight connections to drain before returning ctx.Err(); each handler closes
// its own connection on cancellation, so a peer blocked mid-conversation cannot
// hold the drain open.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		_ = l.Close()
	}()

	var wg sync.WaitGroup
	for {
		conn, err := l.Accept()
		if err != nil {
			wg.Wait()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("netd accept: %w", err)
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			s.log.Warn("netd: rejecting non-unix connection")
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleConn(ctx, uc)
		}()
	}
}

// handleConn authenticates the peer and serves framed requests on conn until the
// peer disconnects, a frame is unreadable, the connection sits idle past
// IdleTimeout, or ctx is cancelled. A recover guards the whole connection so no
// malformed input can ever crash the daemon (the robust, allocation-bounded
// decoder returns errors rather than panicking; the recover is the
// belt-and-suspenders backstop).
//
// Two mechanisms bound the handler's lifetime, and both are needed. A blocking
// read does not observe ctx, so cancellation reaches it only through the fd: a
// watcher goroutine closes conn on ctx.Done, which fails the in-flight read and
// lets Serve's drain complete. That covers shutdown; it does not cover a daemon
// that keeps running while a peer dies silently, so every read is additionally
// armed with an IdleTimeout deadline.
func (s *Server) handleConn(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("netd: recovered from handler panic", "panic", r)
		}
	}()

	// stop retires the watcher when the handler returns on its own. The deferred
	// close runs before the deferred conn.Close (defers are LIFO), so the watcher
	// is gone before the fd is; a double Close is harmless in any case.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()

	if err := s.peer.Verify(conn); err != nil {
		s.log.Warn("netd: peer rejected", "err", err)
		return
	}
	s.log.Debug("netd: peer accepted")

	st := newConnState(s.cfg.MaxPerConn)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := conn.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout)); err != nil {
			s.log.Debug("netd: arming read deadline", "err", err)
			return
		}
		payload, err := wire.ReadFrame(conn, s.cfg.MaxRequestBytes)
		if err != nil {
			switch {
			case errors.Is(err, os.ErrDeadlineExceeded):
				s.log.Debug("netd: reaping idle connection", "idle", s.cfg.IdleTimeout)
			case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			default:
				s.log.Debug("netd: connection closed", "err", err)
			}
			return
		}
		resp, file := s.dispatch(ctx, st, payload)
		if file != nil {
			if err := s.writeResponseWithFD(conn, resp, file); err != nil {
				s.log.Error("netd: send fd response", "err", err)
			}
			_ = file.Close()
			continue
		}
		if err := s.writeResponse(conn, resp); err != nil {
			s.log.Debug("netd: send response", "err", err)
			return
		}
	}
}

// dispatch decodes one request payload and routes it to its handler. A decode
// failure, an incompatible major version, or an unknown verb yields an error
// response (never a panic). The returned *os.File is non-nil only for a successful
// BindPort (the fd to pass to the client).
func (s *Server) dispatch(ctx context.Context, st *connState, payload []byte) (wire.Response, *os.File) {
	var req wire.Request
	if err := json.Unmarshal(payload, &req); err != nil {
		return s.errResp(fmt.Sprintf("decode request: %v", err)), nil
	}
	if !req.Version.Compatible() {
		return s.errResp(fmt.Sprintf("incompatible protocol major: client %d.%d, server %d.%d",
			req.Version.Major, req.Version.Minor, wire.ProtocolVersionMajor, wire.ProtocolVersionMinor)), nil
	}
	switch req.Verb {
	case wire.VerbEnsureAlias:
		return s.handleEnsureAlias(ctx, st, req.EnsureAlias), nil
	case wire.VerbRemoveAlias:
		return s.handleRemoveAlias(ctx, st, req.RemoveAlias), nil
	case wire.VerbConfigureMesh:
		return s.handleConfigureMesh(ctx, st, req.ConfigureMesh), nil
	case wire.VerbRemoveMesh:
		return s.handleRemoveMesh(ctx), nil
	case wire.VerbLoadPFAnchor:
		return s.handleLoadPFAnchor(ctx, req.LoadPFAnchor), nil
	case wire.VerbBindPort:
		return s.handleBindPort(ctx, st, req.BindPort)
	default:
		return s.errResp(fmt.Sprintf("unknown verb %q", req.Verb)), nil
	}
}

// handleEnsureAlias validates the IP against the alias policy, accounts it against
// the per-connection cap, and plumbs the alias.
func (s *Server) handleEnsureAlias(ctx context.Context, st *connState, args *wire.EnsureAliasArgs) wire.Response {
	if args == nil {
		return s.errResp("ensureAlias: missing args")
	}
	ip, err := netip.ParseAddr(args.IP)
	if err != nil {
		return s.errResp(fmt.Sprintf("ensureAlias: parse ip %q: %v", args.IP, err))
	}
	if err := s.validateAliasIP(ip); err != nil {
		s.log.Warn("netd: alias rejected", "ip", ip.String(), "err", err)
		return s.errResp(err.Error())
	}
	if err := st.addAlias(ip); err != nil {
		return s.errResp(err.Error())
	}
	if err := s.priv.EnsureAlias(ctx, ip); err != nil {
		st.removeAlias(ip)
		return s.errResp(fmt.Sprintf("ensureAlias: %v", err))
	}
	s.log.Info("netd: alias ensured", "ip", ip.String())
	return s.okResp()
}

// handleRemoveAlias validates the IP (so an out-of-policy address cannot be used to
// probe lo0) and removes the alias.
func (s *Server) handleRemoveAlias(ctx context.Context, st *connState, args *wire.RemoveAliasArgs) wire.Response {
	if args == nil {
		return s.errResp("removeAlias: missing args")
	}
	ip, err := netip.ParseAddr(args.IP)
	if err != nil {
		return s.errResp(fmt.Sprintf("removeAlias: parse ip %q: %v", args.IP, err))
	}
	if err := s.validateAliasIP(ip); err != nil {
		s.log.Warn("netd: alias remove rejected", "ip", ip.String(), "err", err)
		return s.errResp(err.Error())
	}
	if err := s.priv.RemoveAlias(ctx, ip); err != nil {
		return s.errResp(fmt.Sprintf("removeAlias: %v", err))
	}
	st.removeAlias(ip)
	s.log.Info("netd: alias removed", "ip", ip.String())
	return s.okResp()
}

// handleConfigureMesh re-validates the typed peers with the existing mesh logic
// (RouteSet/ValidatePlan), enforces aggregate containment on the routes, resolves
// the private key root-side, and applies the rendered plan.
func (s *Server) handleConfigureMesh(ctx context.Context, st *connState, args *wire.ConfigureMeshArgs) wire.Response {
	if args == nil {
		return s.errResp("configureMesh: missing args")
	}
	if s.cfg.MeshKeyResolver == nil {
		return s.errResp("configureMesh: no mesh key resolver configured (refusing — there is no embedded key)")
	}
	specs, err := meshSpecs(args.Peers)
	if err != nil {
		s.log.Warn("netd: mesh peers rejected", "err", err)
		return s.errResp(err.Error())
	}
	plan, err := mesh.ValidatePlan(s.cfg.NodePodCIDR, specs)
	if err != nil {
		s.log.Warn("netd: mesh plan rejected", "err", err)
		return s.errResp(fmt.Sprintf("configureMesh: %v", err))
	}
	for _, r := range plan.Routes {
		if !s.cfg.ClusterAggregate.Contains(r.Addr()) {
			return s.errResp(fmt.Sprintf("%v: mesh route %s outside cluster aggregate %s", ErrPolicy, r, s.cfg.ClusterAggregate))
		}
	}
	if err := st.setMeshRoutes(len(plan.Routes)); err != nil {
		return s.errResp(err.Error())
	}
	key, err := s.cfg.MeshKeyResolver.Resolve(ctx, args.LocalPrivKeyRef)
	if err != nil {
		return s.errResp(fmt.Sprintf("configureMesh: resolve key: %v", err))
	}
	listenPort := args.ListenPort
	if listenPort == 0 {
		listenPort = mesh.DefaultListenPort
	}
	if err := s.priv.ConfigureMesh(ctx, key, listenPort, plan); err != nil {
		return s.errResp(fmt.Sprintf("configureMesh: %v", err))
	}
	s.log.Info("netd: mesh configured", "peers", len(plan.Peers), "routes", len(plan.Routes))
	return s.okResp()
}

// handleRemoveMesh tears the mesh down.
func (s *Server) handleRemoveMesh(ctx context.Context) wire.Response {
	if err := s.priv.RemoveMesh(ctx); err != nil {
		return s.errResp(fmt.Sprintf("removeMesh: %v", err))
	}
	s.log.Info("netd: mesh removed")
	return s.okResp()
}

// handleLoadPFAnchor validates the clamp against the mesh link MSS bounds and loads
// the anchor (the rule text is rendered daemon-side from the clamp).
func (s *Server) handleLoadPFAnchor(ctx context.Context, args *wire.LoadPFAnchorArgs) wire.Response {
	if args == nil {
		return s.errResp("loadPFAnchor: missing args")
	}
	if err := validateMSSClamp(args.MSSClamp); err != nil {
		s.log.Warn("netd: pf clamp rejected", "mss", args.MSSClamp, "err", err)
		return s.errResp(err.Error())
	}
	if err := s.priv.LoadPFAnchor(ctx, args.MSSClamp); err != nil {
		return s.errResp(fmt.Sprintf("loadPFAnchor: %v", err))
	}
	s.log.Info("netd: pf clamp anchor loaded", "mss", args.MSSClamp)
	return s.okResp()
}

// handleBindPort validates the address (specific, never wildcard — a wildcard
// NodePort is bound in-process by the proxy, never here) and authorizes the port
// (the PortAuthorizer gates a privileged <1024 infra-VIP port; a specific-address
// >=1024 VIP port is allowed), then binds and returns the listening socket fd for
// the server to pass over SCM_RIGHTS.
func (s *Server) handleBindPort(ctx context.Context, st *connState, args *wire.BindPortArgs) (wire.Response, *os.File) {
	if args == nil {
		return s.errResp("bindPort: missing args"), nil
	}
	if args.Port < 1 || args.Port > 65535 {
		return s.errResp(fmt.Sprintf("bindPort: port %d out of range", args.Port)), nil
	}
	addr, err := netip.ParseAddr(args.NodeAddr)
	if err != nil {
		return s.errResp(fmt.Sprintf("bindPort: parse nodeAddr %q: %v", args.NodeAddr, err)), nil
	}
	if addr.IsUnspecified() || addr.IsMulticast() {
		return s.errResp(fmt.Sprintf("%v: bindPort requires a specific non-wildcard address, got %s", ErrPolicy, addr)), nil
	}
	network := args.Protocol
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" && network != "udp" {
		return s.errResp(fmt.Sprintf("bindPort: unsupported protocol %q", network)), nil
	}
	if err := s.authorizePort(ctx, args.Port, args.NodeAddr); err != nil {
		s.log.Warn("netd: port bind rejected", "port", args.Port, "addr", args.NodeAddr, "err", err)
		return s.errResp(err.Error()), nil
	}
	if err := st.addBoundPort(); err != nil {
		return s.errResp(err.Error()), nil
	}
	ap := netip.AddrPortFrom(addr, uint16(args.Port))
	file, err := s.priv.BindPort(ctx, network, ap)
	if err != nil {
		st.removeBoundPort()
		return s.errResp(fmt.Sprintf("bindPort: %v", err)), nil
	}
	s.log.Info("netd: port bound", "network", network, "addr", ap.String())
	resp := s.okResp()
	resp.FDPassed = true
	resp.BoundAddr = ap.String()
	return resp, file
}

// validateAliasIP enforces the alias policy: an IPv4 /32 host that is within BOTH
// the pinned cluster aggregate AND this node's podCIDR (a pod IP), or — when a
// Service CIDR is configured — within it (a proxy VIP). It reuses the pinned
// podnet.ClusterPodCIDR aggregate as the outer bound.
func (s *Server) validateAliasIP(ip netip.Addr) error {
	if !ip.Is4() {
		return fmt.Errorf("%w: alias %s is not an IPv4 /32", ErrPolicy, ip)
	}
	if ip.IsMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("%w: alias %s is not a unicast host", ErrPolicy, ip)
	}
	if s.cfg.ClusterAggregate.Contains(ip) && s.cfg.NodePodCIDR.Contains(ip) {
		return nil
	}
	if s.cfg.ServiceCIDR.IsValid() && s.cfg.ServiceCIDR.Contains(ip) {
		return nil
	}
	return fmt.Errorf("%w: alias %s not in node podCIDR %s (aggregate %s) or service CIDR",
		ErrPolicy, ip, s.cfg.NodePodCIDR, s.cfg.ClusterAggregate)
}

// authorizePort applies the BindPort policy to a SPECIFIC-address bind (handleBindPort
// has already rejected the wildcard). The contract is self-consistent with the real
// consumers: a privileged (<1024) port — the infra VIPs 10.43.0.1:443 / 10.43.0.10:53,
// which are the proxy's ONLY helper-bound ports (pkg/proxy netdBinder routes only
// <1024 here, binding >=1024 itself) — is the escalation-sensitive case and must be
// confirmed against the authoritative Service set by the PortAuthorizer (a nil
// authorizer denies it, fail-safe). A non-privileged (>=1024) specific-address VIP
// port grants no more than the unprivileged service uid could bind itself, so it is
// allowed. There is deliberately no NodePort-range branch: a NodePort is reached on
// the wildcard *:nodePort, which the proxy binds in-process (it needs no privilege)
// and which this daemon rejects as a wildcard — the helper has no NodePort path.
func (s *Server) authorizePort(ctx context.Context, port int, nodeAddr string) error {
	if port < 1024 {
		if s.cfg.PortAuthorizer == nil {
			return fmt.Errorf("%w: privileged port %d denied (no port authorizer configured)", ErrPolicy, port)
		}
		if err := s.cfg.PortAuthorizer.Authorize(ctx, port, nodeAddr); err != nil {
			return fmt.Errorf("%w: privileged port %d not authorized: %v", ErrPolicy, port, err)
		}
		return nil
	}
	return nil
}

// validateMSSClamp bounds the clamp to a sane TCP MSS window: at least minMSSClamp
// and no larger than the mesh link's own max MSS (a larger clamp would be a no-op
// that defeats the anchor's purpose).
func validateMSSClamp(mss int) error {
	max := mesh.MaxMSS(mesh.MTU)
	if mss < minMSSClamp || mss > max {
		return fmt.Errorf("%w: mss clamp %d outside [%d,%d]", ErrPolicy, mss, minMSSClamp, max)
	}
	return nil
}

// meshSpecs converts the typed wire peers into netv1.MeshPeerSpec for the mesh
// validation/rendering logic. Each peer's AllowedIPs are its pod /24; the first
// entry is taken as the podCIDR (mesh.AllowedIPsMatchCIDR, invoked by ValidatePlan,
// then asserts every AllowedIPs entry equals it). The NodeName is set to the
// podCIDR so logs and skip reasons identify the peer.
func meshSpecs(peers []wire.MeshPeerArg) ([]netv1.MeshPeerSpec, error) {
	specs := make([]netv1.MeshPeerSpec, 0, len(peers))
	for i, p := range peers {
		if len(p.AllowedIPs) == 0 {
			return nil, fmt.Errorf("%w: mesh peer %d has no allowedIPs", ErrPolicy, i)
		}
		podCIDR := p.AllowedIPs[0]
		specs = append(specs, netv1.MeshPeerSpec{
			SchemaVersion: netv1.MeshPeerSchemaVersion,
			NodeName:      podCIDR,
			PublicKey:     p.PubKey,
			Endpoint:      p.Endpoint,
			PodCIDR:       podCIDR,
			AllowedIPs:    p.AllowedIPs,
		})
	}
	return specs, nil
}

// okResp builds a success response stamped with the current version.
func (s *Server) okResp() wire.Response {
	return wire.Response{Version: wire.CurrentVersion(), OK: true}
}

// errResp builds a rejection response carrying msg.
func (s *Server) errResp(msg string) wire.Response {
	return wire.Response{Version: wire.CurrentVersion(), OK: false, Error: msg}
}

// writeResponse sends a framed JSON response.
func (s *Server) writeResponse(conn *net.UnixConn, resp wire.Response) error {
	payload, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("encode response: %w", err)
	}
	return wire.WriteFrame(conn, payload)
}

// writeResponseWithFD sends a framed JSON response together with file's descriptor
// in a single SCM_RIGHTS control message, so the client receives both atomically.
func (s *Server) writeResponseWithFD(conn *net.UnixConn, resp wire.Response, file *os.File) error {
	payload, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("encode response: %w", err)
	}
	rights := unix.UnixRights(int(file.Fd()))
	if _, _, err := conn.WriteMsgUnix(wire.Frame(payload), rights, nil); err != nil {
		return fmt.Errorf("write msg with fd: %w", err)
	}
	return nil
}

// connState bounds the live aliases, mesh routes, and bound ports a single
// connection may drive. It is touched only by that connection's single handler
// goroutine, so it needs no lock.
type connState struct {
	max     int
	aliases map[netip.Addr]struct{}
	bound   int
	routes  int
}

// newConnState returns per-connection accounting capped at max.
func newConnState(max int) *connState {
	return &connState{max: max, aliases: make(map[netip.Addr]struct{})}
}

// addAlias records a live alias, rejecting it when the cap is reached (a re-ensure
// of an already-tracked alias is free).
func (c *connState) addAlias(ip netip.Addr) error {
	if _, ok := c.aliases[ip]; ok {
		return nil
	}
	if len(c.aliases) >= c.max {
		return fmt.Errorf("%w: per-connection alias cap %d reached", ErrPolicy, c.max)
	}
	c.aliases[ip] = struct{}{}
	return nil
}

// removeAlias drops a tracked alias.
func (c *connState) removeAlias(ip netip.Addr) {
	delete(c.aliases, ip)
}

// addBoundPort accounts a bound port against the cap.
func (c *connState) addBoundPort() error {
	if c.bound >= c.max {
		return fmt.Errorf("%w: per-connection bound-port cap %d reached", ErrPolicy, c.max)
	}
	c.bound++
	return nil
}

// removeBoundPort releases a bound-port accounting slot (a failed bind).
func (c *connState) removeBoundPort() {
	if c.bound > 0 {
		c.bound--
	}
}

// setMeshRoutes records the route count of the last applied mesh plan, rejecting a
// plan that exceeds the cap.
func (c *connState) setMeshRoutes(n int) error {
	if n > c.max {
		return fmt.Errorf("%w: mesh routes %d exceed per-connection cap %d", ErrPolicy, n, c.max)
	}
	c.routes = n
	return nil
}
