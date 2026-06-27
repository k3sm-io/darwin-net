package wire

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
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
// Client is safe for concurrent use: each call opens its own connection and shares
// no mutable state.
type Client struct {
	socketPath string
	maxResp    int
}

// NewClient returns a Client dialing socketPath; an empty socketPath uses
// DefaultSocketPath. Construction performs no I/O — the socket is dialed per call.
func NewClient(socketPath string) *Client {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	return &Client{socketPath: socketPath, maxResp: DefaultMaxRequestBytes}
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
	conn, err := c.dial(ctx)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()

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
	if !resp.OK {
		return resp, fmt.Errorf("netd %s rejected: %s", req.Verb, resp.Error)
	}
	return resp, nil
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
func (c *Client) ConfigureMesh(ctx context.Context, privKeyRef string, listenPort int, peers []MeshPeerArg) error {
	_, err := c.roundTrip(ctx, Request{
		Version: CurrentVersion(),
		Verb:    VerbConfigureMesh,
		ConfigureMesh: &ConfigureMeshArgs{
			LocalPrivKeyRef: privKeyRef,
			ListenPort:      listenPort,
			Peers:           peers,
		},
	})
	return err
}

// RemoveMesh asks the daemon to tear the wireguard mesh down.
func (c *Client) RemoveMesh(ctx context.Context) error {
	_, err := c.roundTrip(ctx, Request{Version: CurrentVersion(), Verb: VerbRemoveMesh})
	return err
}

// LoadPFAnchor asks the daemon to load the utun-scoped MSS-clamp pf anchor.
func (c *Client) LoadPFAnchor(ctx context.Context, mssClamp int) error {
	_, err := c.roundTrip(ctx, Request{
		Version:      CurrentVersion(),
		Verb:         VerbLoadPFAnchor,
		LoadPFAnchor: &LoadPFAnchorArgs{MSSClamp: mssClamp},
	})
	return err
}

// BindPort asks the daemon to bind a listening socket on the specific addr and
// return it via SCM_RIGHTS. The returned *os.File owns the descriptor; wrap it with
// net.FileListener (TCP) and close the *os.File afterward.
func (c *Client) BindPort(ctx context.Context, network string, addr netip.AddrPort) (*os.File, error) {
	_, file, err := c.roundTripFD(ctx, Request{
		Version: CurrentVersion(),
		Verb:    VerbBindPort,
		BindPort: &BindPortArgs{
			Port:     int(addr.Port()),
			NodeAddr: addr.Addr().String(),
			Protocol: network,
		},
	})
	return file, err
}
