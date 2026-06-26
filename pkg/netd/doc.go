// Package netd is the logic of k3sm's minimal root network daemon (k3sm-netd):
// the ONLY component that performs the irreducibly-root darwin network operations
// (lo0 /32 aliases, the wireguard utun + routes, the pf MSS-clamp anchor, binding
// privileged ports), so everything else runs as the unprivileged _k3sm user and
// reaches it over a unix socket.
//
// It ships as a library, not a main: the production entry is the single signed
// k3sm binary re-exec'd in "netd" mode, which imports Server here. The wire
// protocol and the client live in the leaf sub-package wire; this package is the
// daemon side that authenticates the peer, re-validates every request against
// policy, renders the privileged artifacts, and applies them.
//
// # Why this is the highest-risk surface (and how it is contained)
//
// A root daemon reachable over a local socket is the vmnetd / socket_vmnet LPE CVE
// class. The containment is layered and each layer is unit-tested:
//
//   - Peer authentication at accept. Every connection's peer credential is read
//     with LOCAL_PEERCRED and its uid must equal the authorized service uid;
//     anything else is logged and closed (PeerVerifier). See peercred.go for the
//     defense-in-depth code-identity TODO.
//   - A closed verb set carrying only typed scalars. The protocol never accepts
//     route/pf/wireguard-UAPI text or a filesystem path. The daemon RE-DERIVES and
//     RE-VALIDATES every parameter (CIDR containment via pkg/podnet, the route set
//     via pkg/mesh.RouteSet/ValidatePlan, the port policy) and RENDERS the UAPI and
//     pf rules itself, reusing the existing pkg/podnet and pkg/mesh logic rather
//     than trusting or re-implementing it.
//   - fd-out only. The sole descriptor that ever crosses the socket is the
//     listening socket BindPort returns to the client via SCM_RIGHTS; no inbound fd
//     is ever accepted.
//   - Per-connection resource caps and an allocation-bounded decoder that never
//     panics on malformed input (it returns an error response).
//
// # Selection seam
//
// The unprivileged consumers (pkg/podnet, pkg/proxy, pkg/mesh) each pick the
// netd-backed implementation of their existing seam with one construction-time
// option (WithNetdHelper); the direct ifconfig/route/pfctl implementations remain
// for an explicit run-as-root mode.
package netd
