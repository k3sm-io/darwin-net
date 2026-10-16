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

// Package netd is the logic of k3sm's minimal root network daemon (k3sm-netd):
// the ONLY component that performs the irreducibly-root darwin network operations
// (lo0 /32 aliases, the wireguard utun + routes, binding privileged ports, and the
// interconnect aliases on bridge0), so everything else runs as the unprivileged
// _k3sm user and reaches it over a unix socket.
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
//     route/pf/wireguard-UAPI text, and no filesystem path except the one
//     ApplyUpdate reads from (below). The daemon RE-DERIVES and
//     RE-VALIDATES every parameter (CIDR containment via pkg/podnet, the route set
//     via pkg/mesh.RouteSet/ValidatePlan, the port policy) and RENDERS the UAPI
//     itself, reusing the existing pkg/podnet and pkg/mesh logic rather
//     than trusting or re-implementing it.
//   - Derived, never trusted, interconnect addresses. The interconnect verbs carry
//     only a slot (0..7, so at most 8 aliases on bridge0). The daemon derives the
//     address from its own adopted node identity (netv1alpha1.
//     InterconnectSlotAddress), refuses before adoption and beyond the cable's
//     node-index ceiling, applies it to bridge0 only with no route, removes only
//     aliases it owns (slot 0 last), and at start removes only this node's
//     derived aliases that it does not own.
//   - fd-out only. The sole descriptor that ever crosses the socket is the
//     listening socket BindPort returns to the client via SCM_RIGHTS; no inbound fd
//     is ever accepted.
//   - Per-connection resource caps and an allocation-bounded decoder that never
//     panics on malformed input (it returns an error response).
//
// # ApplyUpdate: the managed update's root step
//
// ApplyUpdate (protocol minor 3) installs a k3sm build set the unprivileged
// agent downloaded and checked. The daemon never fetches anything itself. The
// steps run in this order, and the reply streams one frame per phase:
//
//  1. The caller check. The verb re-reads the peer credential and requires the
//     service uid, whatever PeerVerifier admitted the connection.
//  2. Verifying. The set is copied into a fresh root:wheel 0700 directory
//     directly under DefaultUpdateStagingRoot (/Library/k3sm.staging), under
//     the installer's staging lock. Every directory is opened relative to its
//     parent with O_NOFOLLOW; a symlink, a special file, a set-id file, an entry
//     not owned by the service uid, a file the manifest does not name, or a set
//     over wire.MaxUpdateSetBytes (2 GiB) refuses the update. Permission bits
//     are kept, less group and other write. Every copied file's sha256 must
//     match the manifest, and every manifest file must be present.
//  3. A root-owned log is created beside the set.
//  4. Installing. The staged k3sm, and nothing else from the set, is executed:
//     `<staging>/k3sm install --from-staging <staging>`, plus --allow-downgrade and --require-team-signature when asked. It runs in
//     its own session with its output in the log, holds an inherited copy of
//     the staging lock, and is killed after wire.UpdateInstallTimeout (20 min).
//  5. Done on exit 0, Failed with the log's last lines otherwise; a refusal at
//     any earlier step is Failed with the reason.
//
// An in-place update needs no join token, so none is staged. An ApplyUpdate
// request may be up to wire.MaxApplyUpdateRequestBytes (256 KiB), so a large
// manifest is never why an update fails; every other verb keeps the
// Config.MaxRequestBytes cap.
//
// The installer restarts this daemon, so the connection usually closes during
// Installing; the client reports that as Restarting and the restarted node's
// version is the outcome. The staging directory is removed once the installer
// has returned, or, when the daemon was stopped under it, by the next
// ApplyUpdate (under the staging lock, which a running installer still holds)
// or the uninstall.
//
// # Selection seam
//
// The unprivileged consumers (pkg/podnet, pkg/proxy, pkg/mesh) each pick the
// netd-backed implementation of their existing seam with one construction-time
// option (WithNetdHelper); the direct ifconfig/route/pfctl implementations remain
// for an explicit run-as-root mode.
package netd
