#!/usr/bin/env bash
#
# darwin-net B218 acceptance gate — the connect() source-pinning rung.
#
# THE ITEM (B218): a /32 lo0 alias installs a host route whose
# rt_ifa IS that alias, so XNU source-selects the DESTINATION's own address for an
# UNBOUND dial to another pod. B215 cell P1d measured it: a pod holding
# K3SM_POD_IP=100.64.99.8 dialling 100.64.99.7 was seen by the ACCEPTING side as
# peer=100.64.99.7 — the callee's own IP — so nothing keyed on the source address
# can tell one caller from another. P1d.6 measured the fix: bind(podIP:0) before
# connect(). This rung is that bind, fired ONLY for a destination inside
# K3SM_CLUSTER_CIDRS so an en0-routed external dial is never pinned onto a
# loopback source.
#
# WHAT IT PROVES, AND HOW. pkg/podnet/testdata/bindcases.c grows a second table
# (`… connect <in-dst> <out-dst>`) that dials a set of destinations with and
# without the shim injected. Every verdict is read from the SOCKET —
# getsockname(2) for the source actually selected, getsockopt(SO_REUSEADDR) for
# the option deliberately NOT set here, and accept(2)'s peer address for what a
# PolicyTable would actually see — never from what the shim claims. The
# K3SM_BIND_DEBUG trace is asserted IN ADDITION, so a case proves both the
# outcome and which branch produced it. The same harness binary runs in every
# arm, so any difference between arms is caused by the dylib alone.
#
#   b218.1  BLOCKING  artifacts: the dylib builds and is UNIVERSAL (arm64+x86_64
#                     — dyld hard-terminates a process whose inserted library
#                     lacks its arch), the harness builds, and the host can
#                     source-select for the TEST-NET destinations (below).
#   b218.2  BLOCKING  the PIN branch: an unbound UDP dial into the declared scope
#                     lands on the pod address where the kernel would have chosen
#                     the outbound interface's; a TCP dial into the scope still
#                     COMPLETES and the accepting side sees the pod address as
#                     the peer (the P1d observation, inverted); and the pinned
#                     socket does NOT gain SO_REUSEADDR (the deliberate
#                     divergence from the bind rung, which does set it).
#   b218.3  BLOCKING  the PASSTHROUGH branches, each for its own reason: a
#                     destination OUTSIDE the scope keeps the kernel's own source
#                     (the property that keeps external egress working), an
#                     already-bound socket is left alone, AF_INET6 is out of the
#                     v1 scope, and AF_UNIX + a short addrlen prove the
#                     family/length validation happens before any sockaddr_in
#                     cast.
#   b218.4  BLOCKING  the fail-safe polarity: an UNSET, an UNPARSEABLE, and an
#                     over-long K3SM_CLUSTER_CIDRS, and a missing K3SM_POD_IP,
#                     each reproduce the un-shimmed control output exactly; and
#                     the configured arm DIFFERS from it (the non-vacuity check —
#                     a gate whose arms all agree proves nothing).
#   b218.5  BLOCKING  the Go<->C drift guards, including the new
#                     K3SM_CLUSTER_CIDRS name pin and the MaxClusterCIDRs cap.
#   b218.6  BLOCKING  hack/acceptance/B216.sh still passes — the bind rung shares
#                     this .c, this config struct and this pthread_once, so "did
#                     not regress it" is an assertion, not a hope.
#   b218.7  BLOCKING  this gate parses (`bash -n`).
#
# TIER: integration — it compiles C, loads a dylib, and opens real sockets. It is
# nonetheless HERMETIC and ROOTLESS. K3SM_POD_IP is 127.0.0.1, an address that
# already exists on every host, so no lo0 alias (hence no root) is needed. NO
# PACKET IS SENT to either TEST-NET destination: every case that uses one is
# SOCK_DGRAM, where connect(2) only fills in the pcb. The single case that
# completes a handshake dials a listener the harness itself opened on 127.0.0.1.
#
# WHY TEST-NET DESTINATIONS AT ALL. The rung's claim is about SOURCE selection,
# so a case only discriminates where the kernel's own choice differs from the pod
# address — and a rootless host has exactly one loopback address (127.0.0.2 is
# not bindable without an alias, hence without root). Dialling an RFC 5737
# address makes the kernel select the outbound interface's address, so the
# rewrite to 127.0.0.1 is directly visible. The consequence is a real
# precondition, asserted rather than assumed in b218.1e: the host needs a route
# for those destinations. On a host with no default route this gate FAILS with
# that reason named; it does not skip.
#
# RED BEFORE THE WORK, mutation-verified during authoring (each mutant applied to
# the shim, gate re-run, then reverted):
#   * connect() not registered in the interpose table (the state on main):
#     27/9 — every b218.2 assertion, every trace, and b218.4e.
#   * the destination-scope check removed (pin everything): 34/2 — b218.3a, i.e.
#     an external dial acquires a loopback source.
#   * the scope test INVERTED: 32/4 — b218.2a and b218.3a together.
#   * the rewrite silently not firing (bind elided, trace kept): 34/2 — b218.2a
#     and b218.4e, so a branch that only CLAIMS to fire cannot pass.
#   * the unbound check removed: 35/1 — b218.3b's TRACE, and only the trace. The
#     socket-level outcome is masked because the redundant bind(2) on an
#     already-bound socket fails and the rung falls through to the unpinned
#     connect anyway. That is stated rather than papered over: for THIS mutant
#     the trace assertion is what discriminates, which is why the gate asserts
#     both channels everywhere.
#
# Usage: bash hack/acceptance/B218.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SHIM_SRC="$ROOT/shim/getaddrinfo_shim.c"
HARNESS_SRC="$ROOT/pkg/podnet/testdata/bindcases.c"

echo "==> B218 acceptance (connect() source pinning; repo: $ROOT)"

PASS=0
FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS + 1)); else echo "FAIL  $2"; FAIL=$((FAIL + 1)); fi; }
die() {
	echo "FAIL  $1" >&2
	echo
	echo "==> B218: $PASS passed, $((FAIL + 1)) failed"
	exit 1
}

[ "$(uname -s)" = "Darwin" ] || die "b218.0 this gate exercises a DYLD interpose; it only runs on darwin (uname=$(uname -s))"
command -v clang >/dev/null 2>&1 || die "b218.0 clang is required to build the shim and the case harness"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/b218.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# The pod identity, the declared destination scope, and the two destinations.
# ONE copy of the in-scope/out-of-scope fact: the harness is TOLD which addresses
# to dial, so the env below and the dials cannot drift apart. 127.0.0.0/8 is in
# scope because the live-handshake case dials this process's own loopback
# listener; 192.0.2.0/24 and 198.51.100.0/24 are RFC 5737 TEST-NET-1/2.
POD_IP="127.0.0.1"
CIDRS="127.0.0.0/8,192.0.2.0/24"
IN_DST="192.0.2.7"
OUT_DST="198.51.100.7"

# ==== b218.1 — artifacts ===================================================
if bash "$ROOT/hack/build-shim.sh" "$WORK" >"$WORK/build.log" 2>&1; then
	ladder ok "b218.1a hack/build-shim.sh builds the dylib"
else
	sed 's/^/      /' "$WORK/build.log" >&2
	die "b218.1a hack/build-shim.sh failed"
fi
DYLIB="$WORK/libk3sm_getaddrinfo_shim.dylib"
[ -f "$DYLIB" ] || die "b218.1a the dylib was not produced at $DYLIB"

ARCHES="$(lipo -archs "$DYLIB" 2>/dev/null || echo "")"
if printf '%s' "$ARCHES" | grep -qw arm64 && printf '%s' "$ARCHES" | grep -qw x86_64; then
	ladder ok "b218.1b the dylib is universal (arches: $ARCHES)"
else
	ladder no "b218.1b the dylib is NOT universal (arches: ${ARCHES:-<none>}); dyld would hard-terminate a pod of the missing arch"
fi

HARNESS="$WORK/bindcases"
if clang -arch arm64 -O2 -Wall -Wextra -o "$HARNESS" "$HARNESS_SRC" >"$WORK/harness.log" 2>&1; then
	ladder ok "b218.1c the case harness builds"
else
	sed 's/^/      /' "$WORK/harness.log" >&2
	die "b218.1c compiling $HARNESS_SRC failed"
fi

# The C cap is read from the source so the over-long-list arm below cannot
# silently test the wrong side of the boundary after a bump.
CAP="$(sed -n 's/^#define[[:space:]]\{1,\}K3SM_MAX_CLUSTER_CIDRS[[:space:]]\{1,\}\([0-9]\{1,\}\).*/\1/p' "$SHIM_SRC" | head -1)"
[ -n "$CAP" ] || die "b218.1d no '#define K3SM_MAX_CLUSTER_CIDRS <n>' in $SHIM_SRC"
ladder ok "b218.1d the shim's cluster-CIDR cap is $CAP"

# ==== run the arms =========================================================
# The bind-table arguments (base/low/unix-dir) are unused by the connect table
# but keep ONE argv shape for the harness; any high port will do.
run_arm() { # run_arm <out-basename> [env...]
	local out="$WORK/$1.txt"
	shift
	env "$@" "$HARNESS" 18218 1000 "$WORK" connect "$IN_DST" "$OUT_DST" \
		>"$out" 2>"$WORK/$(basename "$out" .txt).err"
}

run_arm control
run_arm enabled "DYLD_INSERT_LIBRARIES=$DYLIB" "K3SM_POD_IP=$POD_IP" \
	"K3SM_CLUSTER_CIDRS=$CIDRS" "K3SM_BIND_DEBUG=1"
run_arm nocidrs "DYLD_INSERT_LIBRARIES=$DYLIB" "K3SM_POD_IP=$POD_IP" "K3SM_BIND_DEBUG=1"
run_arm badcidrs "DYLD_INSERT_LIBRARIES=$DYLIB" "K3SM_POD_IP=$POD_IP" \
	"K3SM_CLUSTER_CIDRS=192.0.2.0/24,not-a-cidr" "K3SM_BIND_DEBUG=1"
run_arm nopodip "DYLD_INSERT_LIBRARIES=$DYLIB" "K3SM_CLUSTER_CIDRS=$CIDRS" "K3SM_BIND_DEBUG=1"

# An over-long list: CAP+1 entries, each individually valid. The shim must treat
# the whole value as unparseable (never truncate it), so this arm has to behave
# exactly like the unset one.
LONG=""
for i in $(seq 0 "$CAP"); do
	LONG="${LONG:+$LONG,}10.$i.0.0/24"
done
run_arm longcidrs "DYLD_INSERT_LIBRARIES=$DYLIB" "K3SM_POD_IP=$POD_IP" \
	"K3SM_CLUSTER_CIDRS=$LONG" "K3SM_BIND_DEBUG=1"

# val <arm> <case> <key> — read one field of one case line.
val() {
	awk -v want="CASE=$2" -v key="$3" '
		$1 == want {
			for (i = 2; i <= NF; i++) {
				eq = index($i, "=")
				if (substr($i, 1, eq - 1) == key) { print substr($i, eq + 1); exit }
			}
		}
	' "$WORK/$1.txt"
}
# addr <arm> <case> <key> — the same field with its :port stripped, since every
# port in the connect table is kernel-assigned. The ADDRESS is the verdict.
addr() {
	local v
	v="$(val "$1" "$2" "$3")"
	printf '%s' "${v%:*}"
}
# expect <ladder-id> <arm> <case> <key> <want> <why>
expect() {
	local got
	got="$(val "$2" "$3" "$4")"
	if [ "$got" = "$5" ]; then
		ladder ok "$1 $3 $4=$5 — $6"
	else
		ladder no "$1 $3 $4=${got:-<case absent>}, want $5 — $6"
	fi
}
# expect_addr <ladder-id> <arm> <case> <key> <want-addr> <why>
expect_addr() {
	local got
	got="$(addr "$2" "$3" "$4")"
	if [ "$got" = "$5" ]; then
		ladder ok "$1 $3 $4 address=$5 — $6"
	else
		ladder no "$1 $3 $4 address=${got:-<case absent>}, want $5 — $6"
	fi
}
# trace <ladder-id> <arm> <fixed-substring> <why>
trace() {
	if grep -qF -- "$3" "$WORK/$2.err"; then
		ladder ok "$1 trace: $3"
	else
		ladder no "$1 trace missing: $3 — $4"
	fi
}

# b218.1e — the precondition the TEST-NET cases rest on, asserted not assumed.
KERNEL_SRC="$(addr control connect_udp_in_cluster LOCAL)"
if [ "$(val control connect_udp_in_cluster RC)" != "0" ] || [ -z "$KERNEL_SRC" ]; then
	die "b218.1e the un-shimmed control could not source-select for $IN_DST (RC=$(val control connect_udp_in_cluster RC) ERRNO=$(val control connect_udp_in_cluster ERRNO)); this gate needs a route for RFC 5737 destinations — it sends no packet to them, but it does need the kernel to pick a source"
fi
if [ "$KERNEL_SRC" = "$POD_IP" ]; then
	die "b218.1e the kernel already source-selects $POD_IP for $IN_DST, so the pin would be invisible and every b218.2 assertion vacuous"
fi
ladder ok "b218.1e the kernel's own source for $IN_DST is $KERNEL_SRC (≠ the pod address, so a pin is observable)"

# ==== b218.2 — the PIN branch ==============================================
expect_addr b218.2a enabled connect_udp_in_cluster LOCAL "$POD_IP" "an unbound dial INTO the declared scope is source-pinned to the pod address (the kernel would have chosen $KERNEL_SRC)"
expect b218.2a enabled connect_udp_in_cluster RC 0 "…and the dial still succeeds — a pinned failure would be worse than no pin at all"
expect b218.2b enabled connect_udp_in_cluster REUSE 0 "the connect rung does NOT set SO_REUSEADDR (it binds port 0, so the collision the bind rung guards against cannot arise)"
trace b218.2c enabled "dst $IN_DST:9999 -> PIN source $POD_IP" "the pin branch must announce itself"

# The live handshake: a pinned dial must still complete, and the ACCEPTING side
# must see the pod address — the exact observation B215 P1d made, inverted.
expect b218.2d enabled connect_tcp_in_cluster RC 0 "a pinned TCP dial completes a real handshake"
expect_addr b218.2d enabled connect_tcp_in_cluster PEER "$POD_IP" "the accepting side sees the caller's own address — this is what a PolicyTable keyed on the source would read"
trace b218.2e enabled "-> PIN source $POD_IP" "the TCP arm takes the same branch as the UDP one (no SOCK_TYPE special-casing)"

# ==== b218.3 — the PASSTHROUGH branches ====================================
OUT_SRC="$(addr control connect_udp_out_cluster LOCAL)"
expect_addr b218.3a enabled connect_udp_out_cluster LOCAL "$OUT_SRC" "a dial OUTSIDE the declared scope keeps the kernel's own source — pinning it onto a lo0 /32 would black-hole every external dial"
if [ "$OUT_SRC" = "$POD_IP" ]; then
	ladder no "b218.3a the out-of-scope control source is the pod address, so this assertion cannot discriminate"
else
	ladder ok "b218.3a the out-of-scope assertion discriminates (control source $OUT_SRC ≠ pod address $POD_IP)"
fi
trace b218.3a enabled "dst $OUT_DST:9999 -> PASSTHROUGH-NOTCLUSTER" "the destination-scope decline must announce itself"

PRE_SRC="$(addr control connect_udp_prebound LOCAL)"
expect_addr b218.3b enabled connect_udp_prebound LOCAL "$PRE_SRC" "a socket the application already bound is left alone, even for an in-scope destination"
trace b218.3b enabled "-> PASSTHROUGH-BOUND" "the already-bound decline must announce itself"

expect_addr b218.3c enabled connect_inet6_loopback LOCAL "[::1]" "AF_INET6 is out of the rung's v1 scope and passes through untouched"
trace b218.3c enabled "connect fd=4 family=30 len=" "an AF_INET6 destination must be declined on the FAMILY check, before any sockaddr_in cast"

expect b218.3d enabled connect_unix RC -1 "an AF_UNIX connect is passed through before any sockaddr_in cast"
expect b218.3d enabled connect_unix ERRNO 2 "…and the caller sees the kernel's own ENOENT"
trace b218.3d enabled "connect fd=4 family=1 len=" "AF_UNIX must be recognised as a non-rewritable shape"

expect b218.3e enabled connect_short_addrlen RC -1 "a short addrlen is rejected by the kernel, not cast by the shim"
expect b218.3e enabled connect_short_addrlen ERRNO 22 "…with the kernel's own EINVAL"
trace b218.3e enabled "connect fd=4 family=2 len=" "the length validation must fire before the family's rewrite logic"

# ==== b218.4 — the fail-safe polarity, and non-vacuity ======================
# Every port in the connect table is kernel-assigned and differs per run, so
# ports are masked before the arms are compared; nothing else may differ.
norm() { sed -E 's/(LOCAL=[^ ]*):[0-9]+/\1:EPH/; s/(PEER=[^ ]*):[0-9]+/\1:EPH/' "$WORK/$1.txt"; }

diff_arm() { # diff_arm <ladder-id> <arm> <why-it-must-match-control>
	if diff <(norm "$2") <(norm control) >"$WORK/d-$2.txt" 2>&1; then
		ladder ok "$1 the $2 arm reproduces the un-shimmed control exactly — $3"
	else
		sed 's/^/      /' "$WORK/d-$2.txt"
		ladder no "$1 the $2 arm diverged from the un-shimmed control — $3"
	fi
}
diff_arm b218.4a nocidrs "an UNSET K3SM_CLUSTER_CIDRS pins nothing (the rung is off by default)"
diff_arm b218.4b badcidrs "an UNPARSEABLE list disables the whole rung rather than honouring the entries that parsed"
diff_arm b218.4c longcidrs "a list longer than the shim's cap of $CAP is treated as unparseable, never truncated"
diff_arm b218.4d nopodip "no K3SM_POD_IP means no source to pin to, whatever the scope says"

trace b218.4a nocidrs "connect: K3SM_CLUSTER_CIDRS unset" "the off-by-default path must be diagnosable"
trace b218.4b badcidrs "unparseable -> no dial is source-pinned" "an unparseable value must say so rather than fail silently"
trace b218.4c longcidrs "unparseable -> no dial is source-pinned" "an over-long list takes the same unparseable path"

# Non-vacuity: if the configured arm matched the control, every assertion above
# would be describing the kernel's default behaviour. This is the one that reds
# on main.
if diff <(norm enabled) <(norm control) >/dev/null 2>&1; then
	ladder no "b218.4e the configured arm is identical to the un-shimmed control — the connect interpose did nothing (this gate would be vacuous)"
else
	ladder ok "b218.4e the configured arm differs from the un-shimmed control (the interpose is what changes behaviour)"
fi

# ==== b218.5 — the Go<->C drift guards =====================================
if (cd "$ROOT" && GOARCH=arm64 CGO_ENABLED=0 go test ./pkg/podnet/ \
	-run 'TestBindDisciplineEnv|TestBindDisciplineEnvWithCIDRs|TestBindDisciplineEnvUnchangedByCIDRs|TestShimBindEnvNamesMatchC|TestShimMinRewritablePortMatchesC|TestShimMaxClusterCIDRsMatchesC' \
	>"$WORK/gotest.log" 2>&1); then
	ladder ok "b218.5 the pkg/podnet bind/connect ABI drift guards pass"
else
	sed 's/^/      /' "$WORK/gotest.log"
	ladder no "b218.5 the pkg/podnet bind/connect ABI drift guards failed"
fi

# ==== b218.6 — the bind rung is not regressed ==============================
# The two rungs share this .c, one config struct and one pthread_once, so this is
# an assertion rather than a hope.
if bash "$HERE/B216.sh" >"$WORK/b216.log" 2>&1; then
	ladder ok "b218.6 hack/acceptance/B216.sh still passes ($(tail -1 "$WORK/b216.log"))"
else
	sed 's/^/      /' "$WORK/b216.log"
	ladder no "b218.6 hack/acceptance/B216.sh regressed"
fi

# ==== b218.7 — this gate parses ============================================
if bash -n "$HERE/B218.sh" 2>"$WORK/parse.log"; then
	ladder ok "b218.7 this gate parses (bash -n)"
else
	sed 's/^/      /' "$WORK/parse.log"
	ladder no "b218.7 this gate does not parse"
fi

echo
echo "==> B218: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
