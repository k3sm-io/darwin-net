#!/usr/bin/env bash
# The getaddrinfo shim build tests must run, not skip, on a host that can run them.
#
# TestShimBuildLeavesNoTempDirs (pkg/dns/shim_tmpdir_test.go) and
# TestShimIsUniversalBinary (pkg/dns/shim_arch_test.go) skip through
# requireX86_64Capable when the toolchain cannot emit an x86_64 slice, so the
# unit tier stays green on a host without one. go test without -v prints no SKIP
# line, so a toolchain that loses its x86_64 slice would turn both tests into
# silent passes. This stage runs them in one go test invocation with -v and goes
# RED unless each reports PASS.
#
# It applies only where the tests can run: Apple silicon hardware (hw.optional.arm64,
# which stays 1 under a Rosetta-translated shell, unlike uname -m) with an Xcode or
# Command Line Tools clang that xcrun can find. Anywhere else it says so and exits 0.
#
# RED when any of the tests: reports SKIP; fails; does not run at all (renamed or
# removed, so -run matches nothing for it). Every offending test is named.
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

tests=(TestShimBuildLeavesNoTempDirs TestShimIsUniversalBinary)
pkg=./pkg/dns/

if [ "$(uname -s)" != Darwin ] || [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" != 1 ]; then
	echo "    ${tests[*]}: not an Apple silicon Mac, not required to run here"
	exit 0
fi
if ! xcrun --find clang >/dev/null 2>&1; then
	echo "    ${tests[*]}: xcrun finds no clang, not required to run here"
	exit 0
fi

run_re="^($(IFS='|'; echo "${tests[*]}"))\$"
log="$(mktemp)"
trap 'rm -f "$log"' EXIT
rc=0
# darwin-net is pure Go; the shim tests build the C shim by running clang, not cgo.
CGO_ENABLED=0 go test -race -count=1 -v -run "$run_re" "$pkg" > "$log" 2>&1 || rc=$?

bad=()
for t in "${tests[@]}"; do
	if grep -q -- "--- SKIP: ${t} " "$log"; then
		bad+=("$t skipped")
	elif grep -q -- "--- FAIL: ${t} " "$log"; then
		bad+=("$t failed")
	elif ! grep -q -- "--- PASS: ${t} " "$log"; then
		bad+=("$t did not run")
	fi
done
if [ "$rc" -ne 0 ] && [ "${#bad[@]}" -eq 0 ]; then
	bad+=("go test exited $rc")
fi
if [ "${#bad[@]}" -ne 0 ]; then
	cat "$log" >&2
	for b in "${bad[@]}"; do
		echo "FAIL: [darwin-net] $b on an Apple silicon Mac where xcrun finds clang" >&2
	done
	echo "    a skip means the clang on PATH cannot build the universal getaddrinfo shim (see the SKIP reason above)" >&2
	exit 1
fi
for t in "${tests[@]}"; do echo "    $t: PASS"; done
