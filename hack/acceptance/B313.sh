#!/usr/bin/env bash
#
# darwin-net B313 acceptance gate — pkg/proxy/doc.go's transport-override
# feeder paragraph must describe reality, not the pre-M11 gap it once did.
#
# THE ITEM (B313): pkg/proxy/doc.go's "Published identity vs live transport"
# section used to close with "The feeder is the k3sm assembler (from the guest
# agent's Health lease report) and it does not exist yet, so no override is
# installed today." That premise is stale: k3sm's provider now runs
# transportFeed.observe (pkg/provider/transportoverride.go), invoked from
# observeTransport on every runtime status observation, and it pushes
# RoutingTable.SetTransportOverrides with the whole published-to-live map. This
# gate is docs-only: it asserts the stale phrase is gone, the corrected text
# names both the feeder and the seam it feeds, and the named k3sm symbol it now
# cites is a real, non-test definition in the sibling k3sm tree — so a future
# rename on either side reds this gate instead of leaving the doc to drift
# again.
#
#   b313.1  BLOCKING  the exact stale phrase "and it does not exist yet" is
#                     absent from pkg/proxy/doc.go.
#   b313.2  BLOCKING  doc.go names the feeder call (transportFeed.observe or
#                     observeTransport) AND the seam it feeds
#                     (SetTransportOverrides).
#   b313.3  BLOCKING  the sibling k3sm tree exists at the expected path, and
#                     pkg/provider/transportoverride.go there defines the named
#                     symbol as real (non-test) code.
#   b313.4  BLOCKING  this gate parses (`bash -n`).
#
# RED BEFORE THE WORK: on the pre-fix doc.go, b313.1 fails (the stale phrase is
# present) and b313.2 fails (neither the feeder call nor the seam name appears
# in that paragraph's replacement text).
#
# Usage: bash hack/acceptance/B313.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DOC="$ROOT/pkg/proxy/doc.go"
K3SM_ROOT="$(cd "$ROOT/.." && pwd)/k3sm"
OVERRIDE_SRC="$K3SM_ROOT/pkg/provider/transportoverride.go"

echo "==> B313 acceptance (doc.go transport-override feeder; repo: $ROOT)"

PASS=0
FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS + 1)); else echo "FAIL  $2"; FAIL=$((FAIL + 1)); fi; }
die() {
	echo "FAIL  $1" >&2
	echo
	echo "==> B313: $PASS passed, $((FAIL + 1)) failed"
	exit 1
}

[ -f "$DOC" ] || die "b313.0 $DOC does not exist"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/b313.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# ==== b313.1 — the stale phrase is gone ====================================
if grep -qF -- "and it does not exist yet" "$DOC"; then
	ladder no "b313.1 the stale phrase 'and it does not exist yet' is still present in $DOC"
else
	ladder ok "b313.1 the stale phrase 'and it does not exist yet' is absent from $DOC"
fi

# ==== b313.2 — doc.go names the feeder call and the seam it feeds =========
if grep -qE 'transportFeed\.observe|observeTransport' "$DOC"; then
	ladder ok "b313.2a doc.go names the feeder call (transportFeed.observe or observeTransport)"
else
	ladder no "b313.2a doc.go names neither transportFeed.observe nor observeTransport"
fi
if grep -q 'SetTransportOverrides' "$DOC"; then
	ladder ok "b313.2b doc.go names the seam it feeds (SetTransportOverrides)"
else
	ladder no "b313.2b doc.go does not name SetTransportOverrides"
fi

# ==== b313.3 — the cited k3sm symbol is real, non-test code ================
# A missing sibling tree is a hard failure, never a silent pass: this gate's
# whole point is to catch drift against k3sm, and a skip would defeat that.
if [ ! -d "$K3SM_ROOT" ]; then
	die "b313.3 expected the sibling k3sm tree at $K3SM_ROOT (none found) — this gate cannot verify the cited symbol without it"
fi
ladder ok "b313.3a sibling k3sm tree found at $K3SM_ROOT"

if [ ! -f "$OVERRIDE_SRC" ]; then
	die "b313.3 expected $OVERRIDE_SRC (none found) — the cited transport-override feeder no longer lives where doc.go says it does"
fi
ladder ok "b313.3b $OVERRIDE_SRC exists"

case "$OVERRIDE_SRC" in
*_test.go) die "b313.3c $OVERRIDE_SRC is a _test.go file; doc.go must cite a real definition, not a test" ;;
esac
if grep -qE 'func \(f \*transportFeed\) observe\(' "$OVERRIDE_SRC"; then
	ladder ok "b313.3c transportFeed.observe is defined in $OVERRIDE_SRC"
else
	ladder no "b313.3c no 'func (f *transportFeed) observe(' definition found in $OVERRIDE_SRC"
fi
if grep -qE 'func \(r \*runtimedRuntime\) observeTransport\(' "$OVERRIDE_SRC"; then
	ladder ok "b313.3d observeTransport is defined in $OVERRIDE_SRC"
else
	ladder no "b313.3d no 'func (r *runtimedRuntime) observeTransport(' definition found in $OVERRIDE_SRC"
fi

# ==== b313.4 — this gate parses ============================================
if bash -n "$HERE/B313.sh" 2>"$WORK/parse.log"; then
	ladder ok "b313.4 this gate parses (bash -n)"
else
	sed 's/^/      /' "$WORK/parse.log"
	ladder no "b313.4 this gate does not parse"
fi

echo
echo "==> B313: $PASS passed, $FAIL failed"
if [ "$FAIL" -eq 0 ]; then
	echo "B313: OK"
	exit 0
fi
exit 1
