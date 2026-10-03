#!/usr/bin/env bash
#
# darwin-net B350 acceptance gate: the MTU/MSS audit for the skywalk GSO panic.
#
# ==== THE AUDIT =============================================================
#
# THE EVIDENCE. A joined node (macOS 26.6.2 25G83, Mac14,2) kernel-panicked on
# 2026-09-17 while running the wireguard mesh and its lo0 Service VIPs. The
# panic string is an assertion in the platform's own segmentation-offload path:
#
#   assertion failed: (tx_headroom + state->hlen + mss) <= PP_BUF_SIZE_DEF(pp),
#   file: .../xnu/bsd/skywalk/nexus/netif/nx_netif_gso.c, line: 280
#   @uipc_socket.c:8260
#
# A socket send reached the netif GSO path with a segment whose headroom plus
# header length plus MSS did not fit the packet pool's buffer. It is a bounds
# assertion, not memory pressure, and no k3sm process faulted. The stackshot is
# unsymbolicated, so the evidence does not name the interface or the flow.
#
# THE MTU SPREAD A NODE PRESENTS. Pod addresses and Service VIPs are lo0 aliases
# (lo0 MTU 16384); the mesh utun is 1380 (the apis DefaultMeshMTU), and the
# per-peer pod-CIDR routes inherit the utun's MTU.
#
# CANDIDATE FLOW 1: TCP across the spread. Measured on two joined nodes: every
# SYN that crossed the tunnel carried MSS 1340 (1380 minus the IPv4 and TCP
# headers), including from sockets bound to an lo0 alias. XNU sizes a
# connection's MSS from the route to the destination, not from the source
# address's interface, and a peer pod CIDR routes to the utun. So TCP across
# the mesh needs no pf rule, and the mesh loads none. (Older releases loaded a
# max-mss scrub into the io.k3sm.mesh anchor; pf was enabled but the main
# ruleset referenced only the platform's own anchors, so that rule was never
# evaluated. k3sm does not own pf: it never enables pf and never edits the main
# ruleset. Teardown flushes the legacy anchor as a backstop.) A flow that stays
# on lo0 keeps the loopback MSS by design.
#
# CANDIDATE FLOW 2: UDP paths. Untouched by any MSS: that includes wireguard's
# own transport (the encrypted UDP the utun emits toward the peer's endpoint on
# the physical interface), DNS over UDP, and any pod's UDP. The host also
# carried tunnel interfaces k3sm did not create (MTU 2000 and 1000), so "not
# k3sm's traffic" remains a valid outcome.
#
# WHAT A RECURRENCE MUST CAPTURE. The newest /Library/Logs/DiagnosticReports/
# *.panic (written on the NEXT boot) with its panicString quoted verbatim; and,
# from the running node before or right after the event, the lab-tier evidence
# this script writes: pf status, the main ruleset's anchor references, the
# io.k3sm.mesh anchor content, `netstat -i` (every interface's MTU, including
# tunnels k3sm did not create), `ifconfig` for the mesh utun, and the IPv4 and
# IPv6 route tables (which interface each mesh peer and VIP resolves to).
#
# ==== THE RUNGS =============================================================
#
#   CI TIER (default; no privileges, no cluster)
#   b350.0  BLOCKING  this gate parses (`bash -n`).
#   b350.1  BLOCKING  the mesh loads no pf rule, grepped from non-test Go under
#                     pkg/: every line naming "pfctl" is exactly the teardown
#                     flush `"pfctl", "-a", PFAnchor, "-F", "all"` (no rule
#                     load, no -f, no -e/-E), at least one such line exists, and
#                     the removed loaders LoadPFAnchor and PFMSSClampRule are
#                     absent.
#   b350.2  BLOCKING  audit facts that stay true:
#                     a) no non-test source renders a UDP scrub;
#                     b) no non-test source renders a pf rule on lo0;
#                     c) config.go documents the expected tunnel MSS as
#                        `TunnelMSS = MTU - tcpIPv4HeaderBytes`.
#   b350.3  BLOCKING  the Go gates run green: TestMeshLoadsNoPFAnchor (every
#                     command bring-up plumbing and teardown spawn, recorded
#                     through the device's command seam) and
#                     TestMeshSourceRunsNoPFLoad (the AST-level scan).
#
#   LAB TIER (K3SM_LAB=1, root, a joined node). SKIPS LOUDLY otherwise; a SKIP
#   is never a pass.
#   b350.L1 BLOCKING  pfctl answers (`pfctl -s info` prints a Status line), so
#                     an empty anchor read below is not a pfctl failure.
#   b350.L2 WARN      `pfctl -a io.k3sm.mesh -s rules` is empty. Nothing loads
#                     the anchor now; rules found here are an older release's
#                     inert clamp that the teardown or uninstall flush has not
#                     reached yet, so they are reported, never failed.
#   b350.L3 EVIDENCE  netstat -i, ifconfig <utun>, the route tables, pf status,
#                     the main ruleset's anchors, the anchor content and the
#                     panic-report listing are written to
#                     hack/acceptance/.b350-evidence/<UTC stamp>/
#                     (self-gitignored). A utun MTU other than 1380 is printed
#                     as WARN.
#
# Usage:
#   bash hack/acceptance/B350.sh                                  # CI tier
#   sudo K3SM_LAB=1 GO="$(command -v go)" bash hack/acceptance/B350.sh     # + lab tier
#   (K3SM_MESH_UTUN=utunN pins the mesh interface; default: the first utun at
#   the mesh MTU.)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B350.sh"
CONFIG="$ROOT/pkg/mesh/config.go"
WGDEV="$ROOT/pkg/mesh/device_wireguard.go"
ANCHOR="io.k3sm.mesh"
MESH_MTU=1380
GO="${GO:-go}"

echo "==> B350 acceptance (mesh MTU/MSS audit; repo: $ROOT)"

PASS=0
FAIL=0
SKIP=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS + 1)); else echo "FAIL  $2"; FAIL=$((FAIL + 1)); fi; }
skipped() { echo "SKIP  $1"; SKIP=$((SKIP + 1)); }
warn() { echo "WARN  $1"; }
finish() {
	echo
	echo "==> B350: $PASS passed, $FAIL failed, $SKIP skipped"
	[ "$FAIL" -eq 0 ]
}

for f in "$CONFIG" "$WGDEV"; do
	[ -f "$f" ] || { ladder no "b350.0 required file $f does not exist"; finish; exit 1; }
done

# nontest_grep <ERE>: matches in non-test Go sources under pkg/.
nontest_grep() {
	grep -rnE --include='*.go' --exclude='*_test.go' -- "$1" "$ROOT/pkg" || true
}

# ==== b350.0 the gate parses ===============================================
if bash -n "$SELF"; then
	ladder ok "b350.0 the gate parses"
else
	ladder no "b350.0 bash -n $SELF"
fi

# ==== b350.1 the mesh loads no pf rule =====================================
pf_lines="$(nontest_grep '"pfctl"')"
if [ -z "$pf_lines" ]; then
	ladder no "b350.1 no non-test source names \"pfctl\"; the teardown flush is missing"
else
	bad="$(printf '%s\n' "$pf_lines" | grep -vF '"pfctl", "-a", PFAnchor, "-F", "all"' || true)"
	if [ -z "$bad" ]; then
		ladder ok "b350.1 the only pfctl argv is the teardown flush (-a PFAnchor -F all)"
	else
		ladder no "b350.1 a pfctl argv other than the teardown flush exists: $bad"
	fi
fi
loaders="$(nontest_grep '\b(LoadPFAnchor|PFMSSClampRule)\b')"
if [ -z "$loaders" ]; then
	ladder ok "b350.1 the removed loaders LoadPFAnchor and PFMSSClampRule are absent"
else
	ladder no "b350.1 a removed pf loader is back: $loaders"
fi

# ==== b350.2 audit facts ===================================================
udp="$(nontest_grep 'scrub[^"]*proto udp')"
if [ -z "$udp" ]; then
	ladder ok "b350.2a no non-test source renders a UDP scrub"
else
	ladder no "b350.2a a UDP scrub now exists; the audit's UDP finding is stale: $udp"
fi
lo0="$(nontest_grep '(scrub|pass|block)[^"]* on lo0')"
if [ -z "$lo0" ]; then
	ladder ok "b350.2b no non-test source renders a pf rule on lo0"
else
	ladder no "b350.2b a pf rule on lo0 now exists; the audit's lo0 finding is stale: $lo0"
fi
if grep -qE '^const TunnelMSS = MTU - tcpIPv4HeaderBytes$' "$CONFIG"; then
	ladder ok "b350.2c config.go documents TunnelMSS = MTU - tcpIPv4HeaderBytes"
else
	ladder no "b350.2c config.go no longer defines TunnelMSS = MTU - tcpIPv4HeaderBytes"
fi

# ==== b350.3 the Go gates ==================================================
if (cd "$ROOT" && CGO_ENABLED=0 "$GO" test ./pkg/mesh/ -count=1 \
	-run '^(TestMeshLoadsNoPFAnchor|TestMeshSourceRunsNoPFLoad|TestMeshConstantsAndTunnelMSS)$') >"${TMPDIR:-/tmp}/b350-go.$$" 2>&1; then
	ladder ok "b350.3 TestMeshLoadsNoPFAnchor, TestMeshSourceRunsNoPFLoad, TestMeshConstantsAndTunnelMSS pass"
else
	ladder no "b350.3 the Go gates failed: $(tail -n 20 "${TMPDIR:-/tmp}/b350-go.$$" | tr '\n' ' ')"
fi
rm -f "${TMPDIR:-/tmp}/b350-go.$$"

# ==== LAB TIER =============================================================
if [ "${K3SM_LAB:-}" != 1 ] || [ "$(id -u)" -ne 0 ]; then
	echo "----------------------------------------"
	echo "B350 LAB tier NOT RUN (needs K3SM_LAB=1, root, and a joined node running the mesh)."
	echo "  Run it with:  sudo K3SM_LAB=1 PATH=\"\$PATH\" bash $SELF"
	skipped "b350.L1 pfctl answers: requires root on a joined node"
	skipped "b350.L2 the live $ANCHOR anchor is empty: requires root on a joined node"
	skipped "b350.L3 recurrence evidence collected: requires root on a joined node"
	finish
	exit $?
fi

echo "----------------------------------------"
EVID="$HERE/.b350-evidence/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID"
[ -f "$HERE/.b350-evidence/.gitignore" ] || printf '*\n' >"$HERE/.b350-evidence/.gitignore"
git -C "$HERE/../.." check-ignore -q "hack/acceptance/.b350-evidence/probe" || {
  echo "FAIL  the evidence dir is not git-ignored; refusing to write into a public tree" >&2
  exit 1
}
echo "==> evidence: $EVID"

# Never trust pfctl's exit status alone: the routing side of this mesh shipped a
# defect because route(8) printed its complaint and still exited 0 (see the
# comment on TestKernelRoutesLandOnlyWithAUTUNAddress, pkg/mesh/
# routes_integration_test.go). The anchor is judged by its CONTENT only, and
# only after pf's own status read proves pfctl answers at all.
pfctl -a "$ANCHOR" -s rules >"$EVID/anchor.rules" 2>"$EVID/anchor.stderr" || true
live="$(grep -v '^[[:space:]]*$' "$EVID/anchor.rules" || true)"

# ---- b350.L3 evidence first, so a failing L1/L2 still leaves a record -------
netstat -i >"$EVID/netstat-i.txt" 2>&1 || true
ifconfig -a >"$EVID/ifconfig-a.txt" 2>&1 || true
netstat -rn -f inet >"$EVID/routes-inet.txt" 2>&1 || true
netstat -rn -f inet6 >"$EVID/routes-inet6.txt" 2>&1 || true
pfctl -s info >"$EVID/pf-info.txt" 2>&1 || true
pfctl -s rules >"$EVID/pf-main-rules.txt" 2>&1 || true
pfctl -s Anchors >"$EVID/pf-anchors.txt" 2>&1 || true
# shellcheck disable=SC2012 # a human-read listing, not parsed
ls -lt /Library/Logs/DiagnosticReports/*.panic >"$EVID/panic-reports.txt" 2>&1 || true

utun="${K3SM_MESH_UTUN:-}"
if [ -n "$utun" ] && ! printf '%s' "$utun" | grep -qE '^utun[0-9]+$'; then
  echo "FAIL  K3SM_MESH_UTUN must match utun<N> (got: $utun)" >&2
  exit 1
fi
if [ -z "$utun" ]; then
	utun="$(sed -nE "s/^(utun[0-9]+): .* mtu $MESH_MTU\$/\1/p" "$EVID/ifconfig-a.txt" | head -n1)"
fi
if [ -n "$utun" ]; then
	ifconfig "$utun" >"$EVID/ifconfig-$utun.txt" 2>&1 || true
	mtu="$(sed -nE 's/.* mtu ([0-9]+).*/\1/p' "$EVID/ifconfig-$utun.txt" | head -n1)"
	echo "INFO  mesh utun $utun mtu ${mtu:-unknown}"
	[ "${mtu:-}" = "$MESH_MTU" ] || warn "b350.L3 $utun mtu is ${mtu:-unknown}, not the mesh MTU $MESH_MTU"
else
	warn "b350.L3 no utun at the mesh MTU $MESH_MTU found; set K3SM_MESH_UTUN to pin one"
fi
ladder ok "b350.L3 recurrence evidence written to $EVID"

# ---- b350.L1 pfctl answers --------------------------------------------------
if grep -qE '^Status: (Enabled|Disabled)' "$EVID/pf-info.txt"; then
	ladder ok "b350.L1 pfctl answers ($(grep -E '^Status:' "$EVID/pf-info.txt" | head -n1))"
else
	ladder no "b350.L1 pfctl -s info printed no Status line; an empty anchor read would prove nothing"
	finish
	exit 1
fi

# ---- b350.L2 the legacy anchor is empty -------------------------------------
if [ -z "$live" ]; then
	ladder ok "b350.L2 $ANCHOR anchor is empty"
else
	echo "WARN  b350.L2 $ANCHOR anchor still holds rules (an older release's inert clamp the teardown or uninstall flush has not reached yet): $live"
fi

finish
