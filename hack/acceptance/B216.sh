#!/usr/bin/env bash
#
# darwin-net B216 acceptance gate — the bind() interpose in the pod shim.
#
# THE ITEM (B216): extend shim/getaddrinfo_shim.c with
# an interposed bind() that rewrites a pod's WILDCARD bind onto the pod's own
# /32, so two same-node Pods can both hold :8080 instead of colliding with
# EADDRINUSE. Every branch of that interpose is a BINDING resolution of the plan
# or of the B215 probe wave, and this gate asserts each one separately.
#
# WHAT IT PROVES, AND HOW. A table of sockaddr shapes (pkg/podnet/testdata/
# bindcases.c) is bound with and without the shim injected, and the verdict for
# each case is read from the SOCKET — getsockname(2) for the address actually
# bound and getsockopt(SO_REUSEADDR) for the option actually set — not from what
# the shim claims. The K3SM_BIND_DEBUG trace is asserted IN ADDITION, so a case
# proves both the outcome and which branch produced it. The same harness binary
# runs in every arm, so any difference between arms is caused by the dylib alone.
#
#   b216.1  BLOCKING  artifacts: the dylib builds, is UNIVERSAL (arm64+x86_64 —
#                     dyld hard-terminates a process whose inserted library lacks
#                     its arch), and the case harness builds.
#   b216.2  BLOCKING  the REWRITE branches: AF_INET wildcard, an AF_INET wildcard
#                     UDP socket (B215 P1b), and Go's in6addr_any dual-stack
#                     socket rewritten to the v4-mapped form (B215 P2) — each
#                     landing on the pod address AND carrying SO_REUSEADDR
#                     (B215 P1a, the amendment that made it unconditional).
#   b216.3  BLOCKING  the PASSTHROUGH branches, each for its own recorded reason:
#                     IPV6_V6ONLY=1 (P2-v6only), ports below the floor (P1c's
#                     privilege inversion), an ephemeral bind, a specific local
#                     address, a FOREIGN address (the documented trust-domain
#                     honesty), AF_UNIX, and a short addrlen — the last two
#                     proving the family/length validation happens before any
#                     sockaddr_in cast.
#   b216.4  BLOCKING  the fail-safe polarity: an UNSET and a set-but-UNPARSEABLE
#                     K3SM_POD_IP each reproduce the un-shimmed control output
#                     exactly; and the enabled arm DIFFERS from it (the
#                     non-vacuity check — a gate whose arms all agree proves
#                     nothing).
#   b216.5  BLOCKING  the Go<->C drift guards (pkg/podnet env-name and low-port
#                     pins) pass.
#   b216.6  BLOCKING  this gate parses (`bash -n`).
#
# TIER: integration — it compiles C, loads a dylib, and binds real sockets. It is
# nonetheless HERMETIC and ROOTLESS: K3SM_POD_IP is 127.0.0.1, an address that
# already exists on every host, so no lo0 alias (hence no root) is needed. What
# the interpose keys on is "specific vs wildcard", which 127.0.0.1 satisfies; the
# live 100.64/10 pod-address behaviour is B215's recorded lab evidence and B217's
# two-pod e2e gate, not this one's job.
#
# RED BEFORE THE WORK: on main (no bind interpose) the enabled arm is identical
# to the control, so every b216.2 assertion fails and b216.4e (non-vacuity)
# fails. Removing any single branch reds its own assertion — verified by mutation
# during authoring.
#
# Usage: bash hack/acceptance/B216.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SHIM_SRC="$ROOT/shim/getaddrinfo_shim.c"
HARNESS_SRC="$ROOT/pkg/podnet/testdata/bindcases.c"

echo "==> B216 acceptance (bind() interpose; repo: $ROOT)"

PASS=0
FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS + 1)); else echo "FAIL  $2"; FAIL=$((FAIL + 1)); fi; }
die() {
	echo "FAIL  $1" >&2
	echo
	echo "==> B216: $PASS passed, $((FAIL + 1)) failed"
	exit 1
}

[ "$(uname -s)" = "Darwin" ] || die "b216.0 this gate exercises a DYLD interpose; it only runs on darwin (uname=$(uname -s))"
command -v clang >/dev/null 2>&1 || die "b216.0 clang is required to build the shim and the case harness"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/b216.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# ==== b216.1 — artifacts ===================================================
if bash "$ROOT/hack/build-shim.sh" "$WORK" >"$WORK/build.log" 2>&1; then
	ladder ok "b216.1a hack/build-shim.sh builds the dylib"
else
	sed 's/^/      /' "$WORK/build.log" >&2
	die "b216.1a hack/build-shim.sh failed"
fi
DYLIB="$WORK/libk3sm_getaddrinfo_shim.dylib"
[ -f "$DYLIB" ] || die "b216.1a the dylib was not produced at $DYLIB"

# The artifact, never the build flags: the flags are what drifted from their own
# comment last time (the sibling assertion pkg/dns TestShimIsUniversalBinary
# makes for the same reason). dyld HARD-TERMINATES a process whose inserted
# library has no slice for its architecture, and B215 recorded exactly that trap
# on this class of host (the Go toolchain reports amd64 under Rosetta).
ARCHES="$(lipo -archs "$DYLIB" 2>/dev/null || echo "")"
if printf '%s' "$ARCHES" | grep -qw arm64 && printf '%s' "$ARCHES" | grep -qw x86_64; then
	ladder ok "b216.1b the dylib is universal (arches: $ARCHES)"
else
	ladder no "b216.1b the dylib is NOT universal (arches: ${ARCHES:-<none>}); dyld would hard-terminate a pod of the missing arch"
fi

HARNESS="$WORK/bindcases"
if clang -arch arm64 -O2 -Wall -Wextra -o "$HARNESS" "$HARNESS_SRC" >"$WORK/harness.log" 2>&1; then
	ladder ok "b216.1c the sockaddr case harness builds"
else
	sed 's/^/      /' "$WORK/harness.log" >&2
	die "b216.1c compiling $HARNESS_SRC failed"
fi

# The low port must actually be below the shim's floor, read from the C source so
# this gate cannot silently test the wrong side of the carve after a bump.
FLOOR="$(sed -n 's/^#define[[:space:]]\{1,\}K3SM_BIND_MIN_PORT[[:space:]]\{1,\}\([0-9]\{1,\}\).*/\1/p' "$SHIM_SRC" | head -1)"
[ -n "$FLOOR" ] || die "b216.1d no '#define K3SM_BIND_MIN_PORT <n>' in $SHIM_SRC"

# ==== run the arms =========================================================
POD_IP="127.0.0.1"
run_arm() { # run_arm <out> <base> <low> [env...]
	local out="$1" base="$2" low="$3"
	shift 3
	env "$@" "$HARNESS" "$base" "$low" "$WORK" >"$out" 2>"${out%.txt}.err"
}

# A busy port would red an assertion for a reason that has nothing to do with the
# interpose, so pick a base/low pair the un-shimmed control can actually bind.
BASE=""
LOW=""
for cand_base in 18216 18316 18416 18516 18616; do
	for cand_low in $((FLOOR - 7)) $((FLOOR - 11)) $((FLOOR - 15)); do
		run_arm "$WORK/probe.txt" "$cand_base" "$cand_low"
		if ! grep -q 'ERRNO=48' "$WORK/probe.txt"; then
			BASE="$cand_base"
			LOW="$cand_low"
			break 2
		fi
	done
done
[ -n "$BASE" ] || die "b216.1d no free port pair found for the case table (every candidate returned EADDRINUSE)"
[ "$LOW" -lt "$FLOOR" ] || die "b216.1d low port $LOW is not below the shim floor $FLOOR"
ladder ok "b216.1d port pair chosen (base $BASE, low $LOW, shim floor $FLOOR)"

run_arm "$WORK/enabled.txt" "$BASE" "$LOW" \
	"DYLD_INSERT_LIBRARIES=$DYLIB" "K3SM_POD_IP=$POD_IP" "K3SM_BIND_DEBUG=1"
run_arm "$WORK/unset.txt" "$BASE" "$LOW" \
	"DYLD_INSERT_LIBRARIES=$DYLIB" "K3SM_BIND_DEBUG=1"
run_arm "$WORK/garbage.txt" "$BASE" "$LOW" \
	"DYLD_INSERT_LIBRARIES=$DYLIB" "K3SM_POD_IP=not-an-ip" "K3SM_BIND_DEBUG=1"
run_arm "$WORK/control.txt" "$BASE" "$LOW"

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
# trace <ladder-id> <arm> <fixed-substring> <why>
trace() {
	if grep -qF -- "$3" "$WORK/$2.err"; then
		ladder ok "$1 trace: $3"
	else
		ladder no "$1 trace missing: $3 — $4"
	fi
}

# ==== b216.2 — the REWRITE branches ========================================
expect b216.2a enabled af_inet_wildcard LOCAL "$POD_IP:$BASE" "an AF_INET wildcard bind lands on the pod address"
expect b216.2a enabled af_inet_wildcard REUSE 1 "SO_REUSEADDR is set on the rewritten socket (B215 P1a, unconditional)"
expect b216.2b enabled af_inet_udp_wildcard LOCAL "$POD_IP:$((BASE + 1))" "a UDP wildcard bind is rewritten too (B215 P1b: the claim is not TCP-scoped)"
expect b216.2b enabled af_inet_udp_wildcard REUSE 1 "Go sets SO_REUSEADDR on stream listeners only, so UDP needs it from the shim"
expect b216.2c enabled af_inet6_any_dual LOCAL "[::ffff:$POD_IP]:$((BASE + 7))" "Go's in6addr_any dual-stack socket is rewritten to the v4-mapped pod address (B215 P2)"
expect b216.2c enabled af_inet6_any_dual REUSE 1 "the v6 rewrite path sets SO_REUSEADDR as well"
trace b216.2d enabled "AF_INET wildcard :$BASE -> REWRITE $POD_IP:$BASE" "the v4 rewrite branch must announce itself"
trace b216.2e enabled "(v6only=0) -> REWRITE [::ffff:$POD_IP]:$((BASE + 7))" "the v6 rewrite branch must announce itself, and only after the V6ONLY check"

# ==== b216.3 — the PASSTHROUGH branches ====================================
expect b216.3a enabled af_inet6_any_v6only LOCAL "[::]:$((BASE + 8))" "an IPV6_V6ONLY=1 socket is left untouched (B215 P2-v6only)"
expect b216.3a enabled af_inet6_any_v6only REUSE 0 "a passed-through socket must not gain SO_REUSEADDR either"
trace b216.3a enabled "IPV6_V6ONLY=1 -> PASSTHROUGH-V6ONLY" "the v6-only escape is silent by construction; the trace is its only diagnostic"

expect b216.3b enabled af_inet_lowport LOCAL "0.0.0.0:$LOW" "a wildcard bind below the floor stays wildcard (B215 P1c: a specific low bind is EACCES for a non-root uid)"
expect b216.3b enabled af_inet6_any_lowport LOCAL "[::]:$LOW" "the low-port carve applies on the v6 arm too"
trace b216.3b enabled "AF_INET wildcard :$LOW -> PASSTHROUGH-LOWPORT" "the low-port carve must announce itself"

EPH="$(val enabled af_inet_ephemeral LOCAL)"
case "$EPH" in
0.0.0.0:*) ladder ok "b216.3c af_inet_ephemeral LOCAL=$EPH — an ephemeral (port 0) bind is not source-pinned" ;;
*) ladder no "b216.3c af_inet_ephemeral LOCAL=${EPH:-<case absent>}, want 0.0.0.0:<ephemeral> — pinning a client socket's source is the B218 rung's job, not bind()'s" ;;
esac

expect b216.3d enabled af_inet_specific_local LOCAL "$POD_IP:$((BASE + 4))" "an explicit specific bind is the caller's choice and is preserved"
expect b216.3d enabled af_inet_specific_local REUSE 0 "a passed-through specific bind must NOT gain SO_REUSEADDR"
expect b216.3e enabled af_inet6_specific_local LOCAL "[::1]:$((BASE + 10))" "a specific IPv6 bind is preserved"

# A FOREIGN specific address (192.0.2.7, RFC 5737) is not local, so the real bind
# fails EADDRNOTAVAIL. That failure IS the assertion: had the shim rewritten it,
# the bind would have SUCCEEDED on the pod address. The shim is a discipline, not
# an enforcement boundary — it never redirects a bind the caller chose.
expect b216.3f enabled af_inet_specific_foreign RC -1 "a foreign specific bind is passed through, not redirected onto the pod address"
expect b216.3f enabled af_inet_specific_foreign ERRNO 49 "…and the caller sees the kernel's own EADDRNOTAVAIL, untouched"

UNIXSOCK="$(val enabled af_unix LOCAL)"
if [ "$UNIXSOCK" = "unix:$WORK/b216-11.sock" ]; then
	ladder ok "b216.3g af_unix LOCAL=$UNIXSOCK — AF_UNIX passes through before any sockaddr_in cast"
else
	ladder no "b216.3g af_unix LOCAL=${UNIXSOCK:-<case absent>}, want unix:$WORK/b216-11.sock — a domain-generic bind must not be reinterpreted"
fi
trace b216.3g enabled "family=1 len=" "AF_UNIX must be recognised as a non-rewritable shape"

expect b216.3h enabled af_inet_short_addrlen RC -1 "a short addrlen is rejected by the kernel, not cast by the shim"
expect b216.3h enabled af_inet_short_addrlen ERRNO 22 "…with the kernel's own EINVAL"
trace b216.3h enabled "family=2 len=" "the length validation must fire before the family's rewrite logic"

# ==== b216.4 — the fail-safe polarity, and non-vacuity ======================
# The ephemeral port is kernel-assigned and differs per run, so it is masked
# before the arms are compared; nothing else may differ.
norm() { sed 's/^\(CASE=af_inet_ephemeral RC=0 ERRNO=0 LOCAL=0\.0\.0\.0\):[0-9]*/\1:EPHEMERAL/' "$WORK/$1.txt"; }

if diff <(norm unset) <(norm control) >"$WORK/d1.txt" 2>&1; then
	ladder ok "b216.4a an UNSET K3SM_POD_IP reproduces the un-shimmed control exactly"
else
	sed 's/^/      /' "$WORK/d1.txt"
	ladder no "b216.4a an UNSET K3SM_POD_IP changed behaviour — the shim must be transparent when unconfigured"
fi
if diff <(norm garbage) <(norm control) >"$WORK/d2.txt" 2>&1; then
	ladder ok "b216.4b a set-but-UNPARSEABLE K3SM_POD_IP behaves EXACTLY like unset (the pinned fail-safe polarity)"
else
	sed 's/^/      /' "$WORK/d2.txt"
	ladder no "b216.4b a set-but-unparseable K3SM_POD_IP diverged from unset — a malformed env value must never surface to the workload"
fi
trace b216.4c unset "disabled: K3SM_POD_IP unset" "the disabled path must be diagnosable"
trace b216.4d garbage "disabled: K3SM_POD_IP=not-an-ip unparseable" "an unparseable value must say so rather than fail silently"

# Non-vacuity: if the enabled arm matched the control, every assertion above
# would be describing the kernel's default behaviour and this gate would prove
# nothing. This is the assertion that reds on main.
if diff <(norm enabled) <(norm control) >/dev/null 2>&1; then
	ladder no "b216.4e the ENABLED arm is identical to the un-shimmed control — the interpose did nothing (this gate would be vacuous)"
else
	ladder ok "b216.4e the ENABLED arm differs from the un-shimmed control (the interpose is what changes behaviour)"
fi

# ==== b216.5 — the Go<->C drift guards =====================================
if (cd "$ROOT" && GOARCH=arm64 CGO_ENABLED=0 go test ./pkg/podnet/ \
	-run 'TestBindDisciplineEnv|TestShimBindEnvNamesMatchC|TestShimMinRewritablePortMatchesC' \
	>"$WORK/gotest.log" 2>&1); then
	ladder ok "b216.5 the pkg/podnet bind-ABI drift guards pass"
else
	sed 's/^/      /' "$WORK/gotest.log"
	ladder no "b216.5 the pkg/podnet bind-ABI drift guards failed"
fi

# ==== b216.6 — this gate parses ============================================
if bash -n "$HERE/B216.sh" 2>"$WORK/parse.log"; then
	ladder ok "b216.6 this gate parses (bash -n)"
else
	sed 's/^/      /' "$WORK/parse.log"
	ladder no "b216.6 this gate does not parse"
fi

echo
echo "==> B216: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
