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
)

// defaultRPCTimeout bounds a single RPC when the caller's context carries no
// deadline, so a wedged daemon cannot hang a pod-setup or reconcile goroutine
// indefinitely.
const defaultRPCTimeout = 10 * time.Second

// Client is the unprivileged side of the netd RPC: it dials the daemon's unix
// socket and performs one-shot, framed request/response exchanges. One connection
// per call keeps the fd-passing path simple (no interleaving of buffered reads and
// SCM_RIGHTS) and bounds each connection's server-side resource accounting.
//
// Client is safe for concurrent use: each call opens its own connection; the one
// piece of shared state, the daemon version last reported, is guarded by mu.
//
// Every socket the daemon hands over (BindPort) is checked before it is
// returned, because the darwin unix-socket garbage collector can ruin a
// descriptor in flight: when it runs between the daemon's close of its copy and
// this client's recvmsg, it can treat the queued SCM_RIGHTS socket as
// unreachable, sorflush it (the receive buffer limit drops to zero and the
// socket can no longer receive) and still deliver it. Such a socket binds the
// port but never reads a datagram or accepts a connection, so a reader on it
// spins or waits forever. The client reads SO_RCVBUF on every received
// descriptor; zero means flushed, and the descriptor is closed and the verb
// re-issued on a fresh connection (the daemon binds a fresh socket each time),
// up to flushedSocketAttempts times before the call fails with ErrFlushedSocket.
type Client struct {
	socketPath string
	maxResp    int
	// open dials one framed (non-fd) connection: c.dial in production, an
	// in-memory pipe in the unit tests.
	open func(ctx context.Context) (io.ReadWriteCloser, error)
	// exchangeFD performs one fd-carrying exchange on its own connection and
	// returns with that connection closed: c.roundTripFD in production, a fake
	// descriptor source in the unit tests.
	exchangeFD func(ctx context.Context, req Request) (Response, *os.File, error)
	// inspect reads a received socket's state: inspectSocket in production.
	inspect func(fd int) (socketState, error)
	// log receives the flushed-socket warning; nil means slog.Default().
	log *slog.Logger

	mu         sync.Mutex
	helper     Version
	helperSeen bool
}

// HelperVersion returns the protocol version the daemon reported in its most
// recent reply (success or rejection), and false before any reply was decoded. A
// daemon that predates minor 1 reports minor 0.
func (c *Client) HelperVersion() (Version, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.helper, c.helperSeen
}

// observe records the version a decoded reply carried.
func (c *Client) observe(v Version) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.helper, c.helperSeen = v, true
}

// NewClient returns a Client dialing socketPath; an empty socketPath uses
// DefaultSocketPath. Construction performs no I/O — the socket is dialed per call.
func NewClient(socketPath string) *Client {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	c := &Client{socketPath: socketPath, maxResp: DefaultMaxRequestBytes, inspect: inspectSocket}
	c.open = func(ctx context.Context) (io.ReadWriteCloser, error) { return c.dial(ctx) }
	c.exchangeFD = c.roundTripFD
	return c
}

// logger returns the client's logger, slog.Default() when none was set.
func (c *Client) logger() *slog.Logger {
	if c.log != nil {
		return c.log
	}
	return slog.Default()
}

// dial opens a connection to the daemon and arms it with a deadline derived from
// ctx (or defaultRPCTimeout when ctx carries none).
func (c *Client) dial(ctx context.Context) (*net.UnixConn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("dial netd %s: %w", c.socketPath, err)
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("dial netd %s: not a unix connection", c.socketPath)
	}
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(defaultRPCTimeout)
	}
	_ = uc.SetDeadline(dl)
	return uc, nil
}

// roundTrip performs a framed request/response exchange with no fd transfer.
func (c *Client) roundTrip(ctx context.Context, req Request) (Response, error) {
	conn, err := c.open(ctx)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	return c.exchange(conn, req)
}

// exchange writes one request frame on conn and reads and decodes its reply,
// recording the daemon version it carries. A rejection is an error; a named one
// (Response.Reason) wraps its sentinel.
func (c *Client) exchange(conn io.ReadWriter, req Request) (Response, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return Response{}, fmt.Errorf("encode %s request: %w", req.Verb, err)
	}
	if err := WriteFrame(conn, payload); err != nil {
		return Response{}, fmt.Errorf("send %s request: %w", req.Verb, err)
	}
	respBytes, err := ReadFrame(conn, c.maxResp)
	if err != nil {
		return Response{}, fmt.Errorf("read %s response: %w", req.Verb, err)
	}
	var resp Response
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return Response{}, fmt.Errorf("decode %s response: %w", req.Verb, err)
	}
	c.observe(resp.Version)
	if !resp.OK {
		if named := errorOfReason(resp.Reason); named != nil {
			return resp, fmt.Errorf("netd %s rejected: %s: %w", req.Verb, resp.Error, named)
		}
		return resp, fmt.Errorf("netd %s rejected: %s", req.Verb, resp.Error)
	}
	return resp, nil
}

// interconnectRoundTrip sends verb only to a daemon that, on this very
// connection, reported a minor that understands it: Hello first, then the verb
// on the same connection. A version learned on an earlier connection is never
// trusted, because the helper may have been replaced (downgraded) since. A daemon
// older than minor 2 answers Hello "unknown verb" with its version; that is the
// expected probe result, so the client returns ErrHelperTooOld and writes
// nothing more.
func (c *Client) interconnectRoundTrip(ctx context.Context, verb Verb, args InterconnectAliasArgs) (netip.Addr, error) {
	conn, err := c.open(ctx)
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	hello, err := c.exchange(conn, Request{Version: CurrentVersion(), Verb: VerbHello})
	if !hello.Version.SupportsInterconnect() {
		if err != nil && hello.Version == (Version{}) {
			// No decodable reply at all: the probe itself failed.
			return netip.Addr{}, err
		}
		return netip.Addr{}, fmt.Errorf("%w: %s needs minor %d, the helper speaks %d.%d",
			ErrHelperTooOld, verb, MinorInterconnect, hello.Version.Major, hello.Version.Minor)
	}
	if err != nil {
		return netip.Addr{}, err
	}
	req := Request{Version: CurrentVersion(), Verb: verb}
	switch verb {
	case VerbEnsureInterconnectAlias:
		req.EnsureInterconnectAlias = &args
	case VerbRemoveInterconnectAlias:
		req.RemoveInterconnectAlias = &args
	default:
		return netip.Addr{}, fmt.Errorf("netd: %s is not an interconnect verb", verb)
	}
	resp, err := c.exchange(conn, req)
	if err != nil {
		return netip.Addr{}, err
	}
	if resp.InterconnectIP == "" {
		return netip.Addr{}, nil
	}
	addr, err := netip.ParseAddr(resp.InterconnectIP)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("netd %s: reply carries no usable interconnect address %q: %w", verb, resp.InterconnectIP, err)
	}
	return addr, nil
}

// EnsureInterconnectAlias asks the daemon to put slot's interconnect address on
// bridge0 and returns the address the daemon derived. It sends only the slot.
// Against a helper older than minor 2 (as reported on this call's own connection)
// it sends nothing and returns ErrHelperTooOld. A named refusal wraps its
// sentinel (ErrInterconnectIndexOutOfRange and the rest).
func (c *Client) EnsureInterconnectAlias(ctx context.Context, slot int) (netip.Addr, error) {
	return c.interconnectRoundTrip(ctx, VerbEnsureInterconnectAlias, InterconnectAliasArgs{Slot: slot})
}

// RemoveInterconnectAlias asks the daemon to remove slot's interconnect alias
// from bridge0. It sends only the slot, and, like EnsureInterconnectAlias, nothing
// at all to a helper older than minor 2 (ErrHelperTooOld).
func (c *Client) RemoveInterconnectAlias(ctx context.Context, slot int) error {
	_, err := c.interconnectRoundTrip(ctx, VerbRemoveInterconnectAlias, InterconnectAliasArgs{Slot: slot})
	return err
}

// roundTripFD performs a framed request and receives a response that carries a
// single file descriptor via SCM_RIGHTS (the BindPort path). The returned *os.File
// owns the descriptor; the caller closes it.
func (c *Client) roundTripFD(ctx context.Context, req Request) (Response, *os.File, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return Response{}, nil, err
	}
	defer conn.Close()

	payload, err := json.Marshal(req)
	if err != nil {
		return Response{}, nil, fmt.Errorf("encode %s request: %w", req.Verb, err)
	}
	if err := WriteFrame(conn, payload); err != nil {
		return Response{}, nil, fmt.Errorf("send %s request: %w", req.Verb, err)
	}

	buf := make([]byte, c.maxResp)
	oob := make([]byte, unix.CmsgSpace(4)) // room for exactly one fd
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return Response{}, nil, fmt.Errorf("read %s response: %w", req.Verb, err)
	}
	frame, err := ParseFrame(buf[:n])
	if err != nil {
		return Response{}, nil, fmt.Errorf("decode %s response frame: %w", req.Verb, err)
	}
	var resp Response
	if err := json.Unmarshal(frame, &resp); err != nil {
		return Response{}, nil, fmt.Errorf("decode %s response: %w", req.Verb, err)
	}
	c.observe(resp.Version)
	if !resp.OK {
		// Drain any fd the daemon may have sent so we do not leak it on a reject.
		if f := firstFD(oob[:oobn]); f != nil {
			_ = f.Close()
		}
		return resp, nil, fmt.Errorf("netd %s rejected: %s", req.Verb, resp.Error)
	}
	file := firstFD(oob[:oobn])
	if file == nil {
		return resp, nil, ErrNoFD
	}
	return resp, file, nil
}

// flushedSocketAttempts bounds how many handed-over sockets one call accepts
// and discards as flushed before it gives up. The race is rare (about one
// handover in thousands under load), so three in a row means something other
// than the race is wrong. ErrFlushedSocket's final message says "three times";
// keep the two together.
const flushedSocketAttempts = 3

// socketState is what the client reads from a received socket: SO_RCVBUF, the
// pending SO_ERROR, and the local address, for the flushed check and its log.
type socketState struct {
	rcvBuf int
	soErr  int
	local  string
}

// inspectSocket reads fd's state. Only SO_RCVBUF is required; the error and
// the local address are best effort, for the log line.
func inspectSocket(fd int) (socketState, error) {
	rcv, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		return socketState{}, fmt.Errorf("read SO_RCVBUF: %w", err)
	}
	st := socketState{rcvBuf: rcv}
	if v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR); err == nil {
		st.soErr = v
	}
	if sa, err := unix.Getsockname(fd); err == nil {
		switch a := sa.(type) {
		case *unix.SockaddrInet4:
			st.local = netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port)).String()
		case *unix.SockaddrInet6:
			st.local = netip.AddrPortFrom(netip.AddrFrom16(a.Addr), uint16(a.Port)).String()
		}
	}
	return st, nil
}

// roundTripSocket performs an fd-carrying verb and returns a socket the kernel
// has not flushed in flight (see Client). A flushed descriptor is closed and
// the request re-issued on a new connection; the previous exchange's
// connection is already closed by then and the daemon closed its own copy
// right after sending, so the port is free for the daemon's fresh bind.
func (c *Client) roundTripSocket(ctx context.Context, req Request, what string) (Response, *os.File, error) {
	for attempt := 1; ; attempt++ {
		resp, file, err := c.exchangeFD(ctx, req)
		if err != nil {
			return resp, nil, err
		}
		st, err := c.inspect(int(file.Fd()))
		if err != nil {
			_ = file.Close()
			return resp, nil, fmt.Errorf("netd %s %s: inspect the handed-over socket: %w", req.Verb, what, err)
		}
		if st.rcvBuf != 0 {
			return resp, file, nil
		}
		c.logger().Warn("netd: handed-over socket was flushed by the kernel in flight; retrying",
			"verb", req.Verb, "target", what, "local", st.local, "rcvbuf", st.rcvBuf,
			"soError", st.soErr, "attempt", attempt, "maxAttempts", flushedSocketAttempts)
		_ = file.Close()
		if attempt == flushedSocketAttempts {
			return resp, nil, fmt.Errorf("netd %s %s: %w, three times", req.Verb, what, ErrFlushedSocket)
		}
	}
}

// firstFD parses the first file descriptor out of an SCM_RIGHTS control message,
// closing any extras, and wraps it in an *os.File. It returns nil (never panics)
// when oob carries no descriptor.
func firstFD(oob []byte) *os.File {
	if len(oob) == 0 {
		return nil
	}
	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil || len(scms) == 0 {
		return nil
	}
	fds, err := unix.ParseUnixRights(&scms[0])
	if err != nil || len(fds) == 0 {
		return nil
	}
	for _, extra := range fds[1:] {
		_ = unix.Close(extra)
	}
	return os.NewFile(uintptr(fds[0]), "netd-bound-socket")
}

// EnsureAlias asks the daemon to plumb a /32 lo0 alias for ip.
func (c *Client) EnsureAlias(ctx context.Context, ip netip.Addr) error {
	_, err := c.roundTrip(ctx, Request{
		Version:     CurrentVersion(),
		Verb:        VerbEnsureAlias,
		EnsureAlias: &EnsureAliasArgs{IP: ip.String()},
	})
	return err
}

// RemoveAlias asks the daemon to tear a /32 lo0 alias down.
func (c *Client) RemoveAlias(ctx context.Context, ip netip.Addr) error {
	_, err := c.roundTrip(ctx, Request{
		Version:     CurrentVersion(),
		Verb:        VerbRemoveAlias,
		RemoveAlias: &RemoveAliasArgs{IP: ip.String()},
	})
	return err
}

// ConfigureMesh asks the daemon to bring the wireguard mesh up (resolving
// privKeyRef to the private key root-side) and program the typed peers.
//
// nodePodCIDR is the node's own pod /24; the daemon adopts it as its node identity
// when it still holds the pre-join default and nothing is live (see
// ConfigureMeshArgs.NodePodCIDR). The zero Prefix omits the field, which is exactly
// what an older client sends and leaves the daemon's configured identity alone.
func (c *Client) ConfigureMesh(ctx context.Context, privKeyRef string, listenPort int, nodePodCIDR netip.Prefix, peers []MeshPeerArg) error {
	args := &ConfigureMeshArgs{
		LocalPrivKeyRef: privKeyRef,
		ListenPort:      listenPort,
		Peers:           peers,
	}
	if nodePodCIDR.IsValid() {
		args.NodePodCIDR = nodePodCIDR.String()
	}
	_, err := c.roundTrip(ctx, Request{
		Version:       CurrentVersion(),
		Verb:          VerbConfigureMesh,
		ConfigureMesh: args,
	})
	return err
}

// RemoveMesh asks the daemon to tear the wireguard mesh down.
func (c *Client) RemoveMesh(ctx context.Context) error {
	_, err := c.roundTrip(ctx, Request{Version: CurrentVersion(), Verb: VerbRemoveMesh})
	return err
}

// MeshPeerStats asks the daemon for the most recent wireguard handshake its mesh
// device completed with each peer. It changes nothing on the daemon. A daemon
// older than minor 5 answers "unknown verb"; the client then returns an error
// wrapping ErrHelperTooOld. A reply listing more than DefaultMaxPerConn peers is
// refused whole. An entry with an empty key or a non-positive handshake time is
// skipped and the rest returned; only the number skipped is logged, never a
// value from the entry.
func (c *Client) MeshPeerStats(ctx context.Context) ([]MeshPeerStat, error) {
	resp, err := c.roundTrip(ctx, Request{Version: CurrentVersion(), Verb: VerbMeshPeerStats})
	if err != nil {
		if resp.Version != (Version{}) && !resp.Version.SupportsMeshPeerStats() {
			return nil, fmt.Errorf("%w: %s needs minor %d, the helper speaks %d.%d",
				ErrHelperTooOld, VerbMeshPeerStats, MinorMeshPeerStats, resp.Version.Major, resp.Version.Minor)
		}
		return nil, err
	}
	if len(resp.MeshPeerStats) > DefaultMaxPerConn {
		return nil, fmt.Errorf("netd %s: reply lists %d peers, more than the %d allowed", VerbMeshPeerStats, len(resp.MeshPeerStats), DefaultMaxPerConn)
	}
	stats := make([]MeshPeerStat, 0, len(resp.MeshPeerStats))
	for _, st := range resp.MeshPeerStats {
		if st.PubKey == "" || st.LastHandshakeUnixNano <= 0 {
			continue
		}
		stats = append(stats, st)
	}
	if skipped := len(resp.MeshPeerStats) - len(stats); skipped > 0 {
		c.logger().Warn("netd: unusable mesh peer stats skipped", "verb", VerbMeshPeerStats, "skipped", skipped, "read", len(stats))
	}
	return stats, nil
}

// BindPort asks the daemon to bind a listening socket on the specific addr and
// return it via SCM_RIGHTS. The returned *os.File owns the descriptor; wrap it with
// net.FileListener (TCP) and close the *os.File afterward.
//
// A socket the kernel flushed in flight (see Client) is never returned: BindPort
// closes it and asks again, and after three flushed sockets in a row returns an
// error wrapping ErrFlushedSocket.
func (c *Client) BindPort(ctx context.Context, network string, addr netip.AddrPort) (*os.File, error) {
	_, file, err := c.roundTripSocket(ctx, Request{
		Version: CurrentVersion(),
		Verb:    VerbBindPort,
		BindPort: &BindPortArgs{
			Port:     int(addr.Port()),
			NodeAddr: addr.Addr().String(),
			Protocol: network,
		},
	}, network+" "+addr.String())
	return file, err
}

// applyUpdateSlack is the client's allowance beyond UpdateInstallTimeout for
// the verification and extraction that come before the installer runs.
const applyUpdateSlack = 10 * time.Minute

// UpdateResult is the outcome of an ApplyUpdate as this client saw it: the last
// phase (Done, Failed, or Restarting when the stream ended after Installing),
// and the installer's last lines when the daemon sent them.
type UpdateResult struct {
	Phase UpdatePhase
	Log   string
}

// ApplyUpdate asks the daemon to verify and install the signed release in args
// (see ApplyUpdateArgs and VerbApplyUpdate). progress, when not nil, is called
// with each phase the daemon reports, in order. It sends Hello first on the
// same connection and, against a helper older than MinorApplyUpdate, sends
// nothing more and returns ErrHelperTooOld.
//
// On the Installing frame the client acknowledges, once progress has
// returned, with a Hello request on the same connection: the daemon holds the
// installer, which stops the caller's daemon, until that ack arrives or
// updateAckTimeout (in netd) expires. A caller that records the step inside
// progress therefore has it recorded before the installer starts.
//
// A Failed phase is returned as an error wrapping nothing named, with the
// result carrying the phase and the installer's log. A stream that ends after
// Installing with no final frame is not an error: the installer restarts this
// helper, so the result is Restarting and the outcome is the restarted node's
// version. When ctx carries no deadline the call is bounded by
// UpdateInstallTimeout plus a fixed allowance for the verification.
//
// When ctx ends before a terminal frame was read, the connection is closed,
// which ends a blocked read at once, and the error wraps ctx.Err(); the result
// carries the last phase read. A terminal frame read before ctx ended is
// returned as is, and so is a stream end after Installing (Restarting) that
// the read saw before the close.
func (c *Client) ApplyUpdate(ctx context.Context, args ApplyUpdateArgs, progress func(UpdatePhase)) (UpdateResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, UpdateInstallTimeout+applyUpdateSlack)
		defer cancel()
	}
	conn, err := c.open(ctx)
	if err != nil {
		return UpdateResult{}, err
	}
	defer conn.Close()
	// The connection's deadline is the only bound the frame reads otherwise
	// obey, and it is the whole install timeout away. Closing the connection
	// when ctx ends unblocks a pending read or write at once; AfterFunc starts
	// no goroutine unless ctx ends, and stop deregisters it on every return.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	canceled := func(err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("%s: %w", VerbApplyUpdate, cerr)
		}
		return err
	}
	hello, err := c.exchange(conn, Request{Version: CurrentVersion(), Verb: VerbHello})
	if !hello.Version.SupportsApplyUpdate() {
		if err != nil && hello.Version == (Version{}) {
			return UpdateResult{}, canceled(err)
		}
		return UpdateResult{}, fmt.Errorf("%w: %s needs minor %d, the helper speaks %d.%d",
			ErrHelperTooOld, VerbApplyUpdate, MinorApplyUpdate, hello.Version.Major, hello.Version.Minor)
	}
	if err != nil {
		return UpdateResult{}, canceled(err)
	}
	payload, err := json.Marshal(Request{Version: CurrentVersion(), Verb: VerbApplyUpdate, ApplyUpdate: &args})
	if err != nil {
		return UpdateResult{}, fmt.Errorf("encode %s request: %w", VerbApplyUpdate, err)
	}
	if err := WriteFrame(conn, payload); err != nil {
		return UpdateResult{}, canceled(fmt.Errorf("send %s request: %w", VerbApplyUpdate, err))
	}
	var last UpdatePhase
	for {
		raw, err := ReadFrame(conn, c.maxResp)
		if err != nil {
			// The stream's own end after Installing is checked before ctx, so
			// a cancel or the default timeout racing it does not hide
			// Restarting.
			if last == UpdatePhaseInstalling && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
				if progress != nil {
					progress(UpdatePhaseRestarting)
				}
				return UpdateResult{Phase: UpdatePhaseRestarting}, nil
			}
			if cerr := canceled(nil); cerr != nil {
				return UpdateResult{Phase: last}, cerr
			}
			return UpdateResult{Phase: last}, fmt.Errorf("read %s response: %w", VerbApplyUpdate, err)
		}
		var resp Response
		if err := json.Unmarshal(raw, &resp); err != nil {
			return UpdateResult{Phase: last}, fmt.Errorf("decode %s response: %w", VerbApplyUpdate, err)
		}
		c.observe(resp.Version)
		if resp.Phase == "" {
			// A rejection before any phase (a decode or version refusal).
			return UpdateResult{Phase: UpdatePhaseFailed}, fmt.Errorf("netd %s rejected: %s", VerbApplyUpdate, resp.Error)
		}
		last = resp.Phase
		if progress != nil {
			progress(resp.Phase)
		}
		if resp.Phase == UpdatePhaseInstalling {
			c.ackInstalling(conn)
		}
		if !resp.Phase.Terminal() {
			continue
		}
		res := UpdateResult{Phase: resp.Phase, Log: resp.Log}
		if resp.Phase == UpdatePhaseFailed || !resp.OK {
			return res, fmt.Errorf("netd %s failed: %s", VerbApplyUpdate, resp.Error)
		}
		return res, nil
	}
}

// ackInstalling sends the acknowledgement of the Installing frame, a Hello
// request. A failed send is logged and ignored: the daemon runs the installer
// after its bound either way, and the stream's end is read as before.
func (c *Client) ackInstalling(conn io.Writer) {
	payload, err := json.Marshal(Request{Version: CurrentVersion(), Verb: VerbHello})
	if err == nil {
		err = WriteFrame(conn, payload)
	}
	if err != nil {
		c.logger().Debug("netd: acknowledging Installing failed", "err", err)
	}
}
