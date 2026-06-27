package netd

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// ErrPeerUnauthorized is returned by a PeerVerifier when the connecting peer is
// not authorized to drive the daemon. The server logs it and closes the
// connection.
var ErrPeerUnauthorized = errors.New("netd: peer not authorized")

// PeerVerifier authenticates a connection's peer before any request is served. It
// is the consumer seam (defined here, at the daemon) so the production uid check
// can be swapped for a stricter verifier or a test stub. A non-nil error rejects
// the connection.
type PeerVerifier interface {
	// Verify authenticates the peer on conn, returning a non-nil error when the peer
	// is not authorized. It runs once per connection, at accept, before any request.
	Verify(conn *net.UnixConn) error
}

// uidVerifier is the production PeerVerifier: it reads the connected peer's
// credential with getsockopt(SOL_LOCAL, LOCAL_PEERCRED) and requires the peer uid
// to equal the authorized service uid. This is the primary "keep other local
// users out" barrier: once pods run only as the unprivileged _k3sm user via this
// daemon and the verb policy is tight, only that uid may reach the socket.
//
// TODO(security, defense-in-depth, needs cgo): additionally pin the peer's CODE
// IDENTITY — read the peer audit token (LOCAL_PEERTOKEN), build a SecCode with
// SecCodeCreateWithAuditToken, and SecCodeCheckValidity against a designated
// requirement (the signed k3sm binary). That binds the socket to the expected
// program, not just the uid, defeating a same-uid impostor. It is deferred because
// it requires the Security.framework via cgo, and this repo is CGO_ENABLED=0 for
// now; per the security critique it is defense-in-depth layered ON TOP of the uid
// barrier above, which remains the load-bearing control. The PeerVerifier seam is
// exactly where that check slots in.
type uidVerifier struct {
	allowed uint32
}

// newUIDVerifier returns a PeerVerifier that admits only connections whose peer
// uid equals allowed.
func newUIDVerifier(allowed uint32) *uidVerifier {
	return &uidVerifier{allowed: allowed}
}

// Verify reads the peer credential and rejects a uid mismatch.
func (v *uidVerifier) Verify(conn *net.UnixConn) error {
	rc, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("peer-auth: raw conn: %w", err)
	}
	var cred *unix.Xucred
	var credErr error
	if err := rc.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return fmt.Errorf("peer-auth: control: %w", err)
	}
	if credErr != nil {
		return fmt.Errorf("peer-auth: getsockopt LOCAL_PEERCRED: %w", credErr)
	}
	if cred.Uid != v.allowed {
		return fmt.Errorf("%w: peer uid %d != authorized service uid %d", ErrPeerUnauthorized, cred.Uid, v.allowed)
	}
	return nil
}
