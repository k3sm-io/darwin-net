#!/usr/bin/env bash
#
# darwin-net B350 acceptance gate — the MTU/MSS audit for the skywalk GSO panic.
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
# (lo0 MTU 16384); the mesh utun is 1380 (the apis DefaultMeshMTU). A socket
# bound to an lo0 alias derives its MSS from the loopback MTU, so an MSS near
# 16344 can meet a path whose pool buffer is sized for a ~1500-byte frame.
#
# CANDIDATE FLOW 1 — TCP across the spread. Mitigated by the mesh's pf clamp
# (`scrub out on <utun> proto tcp ... max-mss 1340`, pkg/mesh/config.go
# PFMSSClampRule) IF AND ONLY IF that rule is loaded in the io.k3sm.mesh anchor
# AND pf is enabled AND the main ruleset evaluates the anchor. Rendering the rule
# is not the same as it taking effect; the lab tier below reads back the live
# anchor and records pf's status and main-ruleset anchor references for that
# reason. The clamp is scoped to the utun only: lo0 carries no clamp by design
# (clamping loopback would shrink every same-node segment), so a flow that stays
# on lo0 is never clamped.
#
# CANDIDATE FLOW 2 — UDP paths. Structurally uncovered: the scrub rule is
# `proto tcp` and max-mss means nothing to UDP. Any UDP send whose datagram
# exceeds what a segmentation path expects is outside the clamp entirely, and
# that includes wireguard's own transport (the encrypted UDP the utun emits
# toward the peer's endpoint on the physical interface), DNS over UDP, and any
# pod's UDP. The host also carried tunnel interfaces k3sm did not create (MTU
# 2000 and 1000), so "not k3sm's traffic" remains a valid outcome.
#
# WHAT A RECURRENCE MUST CAPTURE. The newest /Library/Logs/DiagnosticReports/
# *.panic (written on the NEXT boot) with its panicString quoted verbatim; and,
# from the running node before or right after the event, the lab-tier evidence
# this script writes: the live io.k3sm.mesh anchor content, pf status and the
# main ruleset's anchor references, `netstat -i` (every interface's MTU,
# including tunnels k3sm did not create), `ifconfig` for the mesh utun, and the
# IPv4 + IPv6 route tables (which interface each mesh peer and VIP resolves to).
#
# ==== THE RUNGS =============================================================
#
#   CI TIER (default; no privileges, no cluster)
#   b350.0  BLOCKING  this gate parses (`bash -n`).
#   b350.1  BLOCKING  the rule rendered by the REAL code path
#                     (hack/acceptance/b350_render.go -> mesh.PFMSSClampRule with
#                     mesh.MSSClamp) is exactly one line, equal to
#                     "scrub out on utun7 proto tcp from any to any max-mss 1340":
#                     scrub, egress, tcp-only, the named interface, MSS 1340.
#                     This pins the rendered TEXT an operator diffs against the
#                     live anchor; pkg/mesh's plan tests already pin the constants.
#   b350.2  BLOCKING  protocol-honesty facts, grepped from the tree:
#                     a) config.go renders the clamp `proto tcp` only, and no
#                        non-test source renders a UDP scrub;
#                     b) no non-test source renders a pf rule on lo0, and the
#                        rule is interface-scoped (`on %s`), so lo0 carries no
#                        clamp by design;
#                     c) the MSS reaches the device: mesh.go sets
#                        `MSS: MSSClamp` in the DeviceConfig it hands NewDevice,
#                        a zero MSS defaults to MSSClamp (the netd path), Up
#                        calls loadPF, and both loaders (device_wireguard.go,
#                        netd applier.go) render through PFMSSClampRule.
#
#   LAB TIER (K3SM_LAB=1, root, a joined node) — SKIPS LOUDLY otherwise; a SKIP
#   is never a pass.
#   b350.L1 BLOCKING  `pfctl -a io.k3sm.mesh -s rules` shows a non-empty anchor.
#   b350.L2 BLOCKING  its CONTENT equals the expected rule for the live utun,
#                     both sides canonicalized by pf itself (`pfctl -nv`).
#   b350.L3 EVIDENCE  netstat -i, ifconfig <utun>, the route tables, pf status,
#                     the main ruleset's anchors and the panic-report listing are
#                     written to hack/acceptance/.b350-evidence/<UTC stamp>/
#                     (self-gitignored). pf disabled, an anchor the main ruleset
#                     does not reference, or a utun MTU other than 1380 are
#                     printed as WARN: the clamp is loaded but not in effect.
#
# Usage:
#   bash hack/acceptance/B350.sh                                  # CI tier
#   sudo K3SM_LAB=1 GO="$(command -v go)" bash hack/acceptance/B350.sh     # + lab tier
#   (K3SM_MESH_UTUN=utunN pins the mesh interface; default: the `on` token of
#   the live anchor rule.)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B350.sh"
RENDER="$HERE/b350_render.go"
CONFIG="$ROOT/pkg/mesh/config.go"
MESH="$ROOT/pkg/mesh/mesh.go"
WGDEV="$ROOT/pkg/mesh/device_wireguard.go"
APPLIER="$ROOT/pkg/netd/applier.go"
ANCHOR="io.k3sm.mesh"
SAMPLE_IF="utun7"
EXPECTED_MSS=1340
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

for f in "$RENDER" "$CONFIG" "$MESH" "$WGDEV" "$APPLIER"; do
	[ -f "$f" ] || { ladder no "b350.0 required file $f does not exist"; finish; exit 1; }
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/b350.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# render <utun> <out-file> — the rule via the real code path (never a literal).
render() {
	(cd "$ROOT" && CGO_ENABLED=0 "$GO" run "$RENDER" "$1") >"$2" 2>"$WORK/render.err"
}

# nontest_grep <ERE> — matches in non-test Go sources under pkg/.
nontest_grep() {
	grep -rnE --include='*.go' --exclude='*_test.go' -- "$1" "$ROOT/pkg" || true
}

# ==== b350.0 — the gate parses =============================================
if bash -n "$SELF"; then
	ladder ok "b350.0 the gate parses"
else
	ladder no "b350.0 bash -n $SELF"
fi

# ==== b350.1 — the rendered rule's content contract ========================
want="scrub out on $SAMPLE_IF proto tcp from any to any max-mss $EXPECTED_MSS"
if render "$SAMPLE_IF" "$WORK/rendered"; then
	lines="$(wc -l <"$WORK/rendered" | tr -d ' ')"
	got="$(cat "$WORK/rendered")"
	if [ "$lines" = 1 ] && [ "$got" = "$want" ]; then
		ladder ok "b350.1 rendered rule is \"$got\""
	else
		ladder no "b350.1 rendered rule drifted: got \"$got\" ($lines line(s)), want \"$want\""
	fi
else
	ladder no "b350.1 could not render the rule: $(tr '\n' ' ' <"$WORK/render.err")"
fi

# ==== b350.2a — the clamp is tcp-only ======================================
if grep -qF 'scrub out on %s proto tcp from any to any max-mss %d' "$CONFIG"; then
	ladder ok "b350.2a config.go renders the clamp 'proto tcp' only"
else
	ladder no "b350.2a config.go no longer renders 'scrub out on %s proto tcp ... max-mss %d'"
fi
udp="$(nontest_grep 'scrub[^"]*proto udp')"
if [ -z "$udp" ]; then
	ladder ok "b350.2a no non-test source renders a UDP scrub (UDP paths are uncovered, as audited)"
else
	ladder no "b350.2a a UDP scrub now exists; the audit's UDP finding is stale: $udp"
fi

# ==== b350.2b — lo0 carries no clamp =======================================
lo0="$(nontest_grep '(scrub|pass|block)[^"]* on lo0')"
if [ -z "$lo0" ]; then
	ladder ok "b350.2b no non-test source renders a pf rule on lo0"
else
	ladder no "b350.2b a pf rule on lo0 now exists; the audit's lo0 finding is stale: $lo0"
fi
if grep -qF '"scrub out on %s ' "$CONFIG"; then
	ladder ok "b350.2b the clamp is interface-scoped ('on %s'), never all interfaces"
else
	ladder no "b350.2b the clamp is no longer scoped 'on %s' in config.go"
fi

# ==== b350.2c — the MSS reaches the device =================================
if grep -qE '^[[:space:]]*MSS:[[:space:]]+MSSClamp,' "$MESH"; then
	ladder ok "b350.2c mesh.go passes MSS: MSSClamp in the DeviceConfig handed to NewDevice"
else
	ladder no "b350.2c mesh.go no longer passes MSS: MSSClamp into DeviceConfig"
fi
if grep -qE '^[[:space:]]*mss = MSSClamp$' "$WGDEV"; then
	ladder ok "b350.2c a zero DeviceConfig.MSS (the netd path) defaults to MSSClamp"
else
	ladder no "b350.2c device_wireguard.go no longer defaults a zero MSS to MSSClamp"
fi
if grep -qF 'd.loadPF(ctx, name)' "$WGDEV" && grep -qF 'PFMSSClampRule(iface, d.cfg.mss)' "$WGDEV"; then
	ladder ok "b350.2c Up loads the anchor, rendering PFMSSClampRule(iface, d.cfg.mss)"
else
	ladder no "b350.2c device_wireguard.go Up/loadPF no longer renders PFMSSClampRule(iface, d.cfg.mss)"
fi
if grep -qF 'mesh.PFMSSClampRule(iface, mssClamp)' "$APPLIER"; then
	ladder ok "b350.2c the netd LoadPFAnchor verb renders through mesh.PFMSSClampRule"
else
	ladder no "b350.2c netd applier.go no longer renders through mesh.PFMSSClampRule"
fi

# ==== LAB TIER =============================================================
if [ "${K3SM_LAB:-}" != 1 ] || [ "$(id -u)" -ne 0 ]; then
	echo "----------------------------------------"
	echo "B350 LAB tier — NOT RUN (needs K3SM_LAB=1, root, and a joined node running the mesh)."
	echo "  Run it with:  sudo K3SM_LAB=1 PATH=\"\$PATH\" bash $SELF"
	skipped "b350.L1 the live $ANCHOR anchor is present — requires root on a joined node"
	skipped "b350.L2 the live anchor content equals the rendered rule — requires root on a joined node"
	skipped "b350.L3 recurrence evidence collected — requires root on a joined node"
	finish
	exit $?
fi

echo "----------------------------------------"
EVID="$HERE/.b350-evidence/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID"
[ -f "$HERE/.b350-evidence/.gitignore" ] || printf '*\n' >"$HERE/.b350-evidence/.gitignore"
git -C "$HERE/../.." check-ignore -q "hack/acceptance/.b350-evidence/probe" || {
  echo "FAIL  the evidence dir is not git-ignored — refusing to write into a public tree" >&2
  exit 1
}
echo "==> evidence: $EVID"

# Never trust pfctl's exit status alone: the routing side of this mesh shipped a
# defect because route(8) printed its complaint and still exited 0 (see the
# comment on TestKernelRoutesLandOnlyWithAUTUNAddress, pkg/mesh/
# routes_integration_test.go). The live anchor is judged by its CONTENT only.
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
	utun="$(printf '%s\n' "$live" | sed -nE 's/.* on (utun[0-9]+) .*/\1/p' | head -n1)"
fi
if [ -n "$utun" ]; then
	ifconfig "$utun" >"$EVID/ifconfig-$utun.txt" 2>&1 || true
	mtu="$(sed -nE 's/.* mtu ([0-9]+).*/\1/p' "$EVID/ifconfig-$utun.txt" | head -n1)"
	echo "INFO  mesh utun $utun mtu ${mtu:-unknown}"
	[ "${mtu:-}" = "$MESH_MTU" ] || warn "b350.L3 $utun mtu is ${mtu:-unknown}, not the mesh MTU $MESH_MTU"
fi
grep -qE '^Status: Enabled' "$EVID/pf-info.txt" || warn "b350.L3 pf is not enabled: a loaded clamp is never evaluated"
grep -qF "$ANCHOR" "$EVID/pf-main-rules.txt" ||
	warn "b350.L3 the main ruleset does not reference $ANCHOR: a loaded clamp is never evaluated"
ladder ok "b350.L3 recurrence evidence written to $EVID"

# ---- b350.L1 the anchor is present -----------------------------------------
if [ -n "$live" ]; then
	ladder ok "b350.L1 $ANCHOR anchor is non-empty"
else
	ladder no "b350.L1 $ANCHOR anchor is absent or empty (stderr: $(tr '\n' ' ' <"$EVID/anchor.stderr"))"
	finish
	exit 1
fi

# ---- b350.L2 the anchor's content equals the rendered rule ------------------
if [ -z "$utun" ]; then
	ladder no "b350.L2 no mesh utun: the live rule names none and K3SM_MESH_UTUN is unset"
	finish
	exit 1
fi
if ! render "$utun" "$EVID/expected.rendered"; then
	ladder no "b350.L2 could not render the expected rule: $(tr '\n' ' ' <"$WORK/render.err")"
	finish
	exit 1
fi
# pf prints rules in its own canonical form ("from any to any" -> "all", plus
# defaults it fills in); -n parses without loading, so both sides go through
# pf's printer before the diff.
pfctl -a "$ANCHOR" -nv -f "$EVID/expected.rendered" 2>/dev/null |
	grep -v '^[[:space:]]*$' >"$EVID/expected.canonical" || true
printf '%s\n' "$live" >"$EVID/live.canonical"
if [ ! -s "$EVID/expected.canonical" ]; then
	ladder no "b350.L2 pfctl -nv produced no canonical form of the expected rule"
elif diff -u "$EVID/expected.canonical" "$EVID/live.canonical" >"$EVID/anchor.diff"; then
	ladder ok "b350.L2 live $ANCHOR content equals the rendered rule for $utun"
else
	ladder no "b350.L2 live $ANCHOR content differs from the rendered rule (see $EVID/anchor.diff)"
	cat "$EVID/anchor.diff"
fi

finish
