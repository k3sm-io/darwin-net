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
//     route/pf/wireguard-UAPI text, and no filesystem path except the archive
//     ApplyUpdate reads (below), whose content is bound to a signed payload. The daemon RE-DERIVES and
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
//     is ever accepted. The daemon closes its copy right after the send, and the
//     client checks every socket it receives: the darwin unix-socket garbage
//     collector can run while the descriptor is in flight, sorflush it (receive
//     buffer limit zero, can no longer receive) and still deliver it, which
//     leaves a socket bound to the port that never reads. The client treats
//     SO_RCVBUF zero as that case, closes the descriptor and asks again on a
//     fresh connection (each BindPort binds a fresh socket, and the closed one no
//     longer holds the port), and fails with wire.ErrFlushedSocket after three.
//   - A specific-address UDP bind coexists with a wildcard. BindPort sets
//     SO_REUSEADDR (never SO_REUSEPORT) on a UDP socket bound to a specific
//     address, because macOS's Internet Sharing resolver (mDNSResponder for the
//     vm network bridge, running whenever a vm pod runs on the Mac) holds the
//     wildcard *:53 and the stack otherwise refuses the DNS VIP 10.43.0.10:53
//     with EADDRINUSE, a race against whichever starts first. The specific socket
//     is the more specific match, so it receives the VIP's datagrams. A wildcard
//     UDP bind and every TCP bind are unchanged (Go already sets SO_REUSEADDR on
//     a TCP listener).
//   - Per-connection resource caps and an allocation-bounded decoder that never
//     panics on malformed input (it returns an error response).
//
// # ApplyUpdate: the managed update's root step
//
// ApplyUpdate (protocol minor 4) installs a k3sm release the cluster's update
// signer authorised. The unprivileged agent downloads the release archive and
// passes its path with the payload the update controller wrote on the Node,
// that payload's signature, and the signer certificate. The daemon fetches
// nothing itself, and nothing the caller computed is trusted: every decision
// comes from the signed payload and from bytes the daemon read itself.
//
// Chain of trust. The archive digest, the release tag, the code-signing policy
// and the downgrade permission are all in the payload, and the payload is
// signed by a key whose certificate (CN k3sm:update-signer, O
// k3sm:update-signers, the Code Signing extended key usage) must chain to the cluster CA the daemon was started with
// (Config.ClusterCAPath, `k3sm netd --cluster-ca`), the system roots excluded.
// Only the server holds that CA's key. So a node that writes its own Node
// annotation, or a process running as the service uid with a tarball of its
// own, cannot authorise an update: it can produce neither a signer certificate
// under the cluster CA nor a signature by one. The server, as the CA holder, is
// already root-equivalent on every node it manages, which is the k3s posture;
// this verb gives it no authority it did not have. A daemon started without a
// cluster CA refuses every ApplyUpdate. One whose CA file is absent or does not
// load re-reads it on each ApplyUpdate until it loads (a fresh server install
// starts this daemon before the cluster PKI exists) and refuses until then; a
// loaded CA is kept.
//
// The steps run in this order, each refusal is a Failed frame with the reason,
// and no step runs after a refusal:
//
//  1. The caller check. The verb re-reads the peer credential and requires the
//     service uid, whatever PeerVerifier admitted the connection.
//  2. Verifying. The signer certificate parses, chains to the cluster CA
//     within its validity, carries the Code Signing extended key usage (a
//     client certificate under the same CA is refused), and names the update
//     signer; the ECDSA signature
//     verifies over sha256 of the payload bytes; the payload decodes strictly
//     and its version is a release tag (v<major>.<minor>.<patch>[-<pre>]).
//  3. The archive is opened with O_NOFOLLOW and must be a regular file the
//     service uid owns, at most wire.MaxUpdateArchiveBytes (512 MiB). Under the
//     installer's staging lock the daemon copies it into an unlinked root-only
//     file, hashing what it writes, and refuses unless that equals the
//     payload's sha256; everything after reads the copy, so the owner of the
//     original cannot change the bytes once they are hashed.
//  4. The daemon extracts the copy itself into a fresh root:wheel 0700
//     directory directly under DefaultUpdateStagingRoot (/Library/k3sm.staging):
//     regular files only, no links, no absolute or ".." paths, the names k3sm,
//     k3sm-execshim, k3sm-vmhost, the two shim dylibs and cp-payload/**, with
//     LICENSE, NOTICE and k3sm-netd read past and any other name refused, and at
//     most wire.MaxUpdateSetBytes (2 GiB) unpacked, skipped members counted.
//  5. The code-signing policy. Every regular file of the staged set must be a
//     Mach-O (thin or universal, FAT_MAGIC_64 included, either byte order):
//     k3sm, k3sm-execshim, k3sm-vmhost, the two shim dylibs and every file
//     under cp-payload/, except the version markers there, which the
//     installer copies as data and never runs (etcd.version, kine.version,
//     zot.version and any later one). A marker is known by its shape, not a
//     list of names: a regular file directly under cp-payload/ whose name ends
//     in .version, smaller than 4 KiB, holding only printable ASCII and
//     newlines. A .version file that is a Mach-O is checked like any other
//     member; anything else that is not a Mach-O, a .version file deeper in
//     cp-payload/ included, is refused before a signature is read. Each Mach-O then goes
//     through /usr/bin/codesign: `--verify --strict`, `-dv` for the Team ID,
//     and, for a Team ID, `--verify --strict -R=` the Developer ID requirement
//     (`anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6]
//     exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists`,
//     with the leaf's subject OU equal to that team). A team counts only when
//     that requirement passes: an ad-hoc, Apple-signed, non-Developer ID or
//     non-Apple-anchored signature that verifies counts as no team. Every
//     member must be validly signed; a team-signed installed
//     /Library/k3sm/k3sm requires that team throughout; an install with no
//     team accepts a tree with no team throughout or one team throughout; the
//     payload's signature: required refuses a tree without a team; a mixed
//     tree is refused. Then, unless the payload allows a downgrade, a version below
//     the installed binary's (`/Library/k3sm/k3sm version`), or one that cannot
//     be ordered against it, is refused.
//  6. Installing. A root-owned log is created beside the set and the staged
//     k3sm, and nothing else from the set, is executed:
//     `<staging>/k3sm install --from-staging <staging>`, plus --allow-downgrade
//     when the payload allows it. The staged installer keeps its own checks as
//     defense in depth; the daemon's are the ones that count. It runs in its
//     own session with its output in the log, holds an inherited copy of the
//     staging lock, and is killed after wire.UpdateInstallTimeout (20 min).
//  7. Done on exit 0, Failed with the log's last lines otherwise.
//
// An in-place update needs no join token, so none is staged. An ApplyUpdate
// request may be up to wire.MaxApplyUpdateRequestBytes (256 KiB); every other
// verb keeps the Config.MaxRequestBytes cap.
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
