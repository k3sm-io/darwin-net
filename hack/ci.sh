#!/usr/bin/env bash
# darwin-net local CI — the docs/GO-STANDARDS.md commit gate in one command.
# The standard CI / pre-commit gate for this repo. Run from anywhere.
#
#   hack/ci.sh [--tier fast|full] [--edited <file>]
#
# --tier picks how the test stage applies hack/quarantine.txt: full (the default)
# reds on every failing test; fast excuses a listed flake outside the packages the
# change edits. --edited names a file with one edited import path per line.
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

test_tier=full
edited_file=""
while [ $# -gt 0 ]; do
	case "$1" in
		--tier) [ $# -ge 2 ] || { echo "usage: hack/ci.sh [--tier fast|full] [--edited <file>]" >&2; exit 2; }; test_tier="$2"; shift 2 ;;
		--edited) [ $# -ge 2 ] || { echo "usage: hack/ci.sh [--tier fast|full] [--edited <file>]" >&2; exit 2; }; edited_file="$2"; shift 2 ;;
		*) echo "usage: hack/ci.sh [--tier fast|full] [--edited <file>]" >&2; exit 2 ;;
	esac
done
case "$test_tier" in fast|full) ;; *) echo "hack/ci.sh: --tier must be fast or full" >&2; exit 2 ;; esac
edited_pkgs=()
if [ -n "$edited_file" ]; then
	[ -r "$edited_file" ] || { echo "hack/ci.sh: --edited $edited_file is not readable" >&2; exit 2; }
	while IFS= read -r p; do
		case "$p" in ''|'#'*) continue ;; esac
		edited_pkgs+=("$p")
	done < "$edited_file"
fi

CGO=0   # darwin-net is pure Go (utun/pf/lo0 via golang.org/x/sys/unix)
STATICCHECK_VERSION=2026.2.2   # keep equal to the install pin in docs/GO-STANDARDS.md §Commit gates
GOVULNCHECK_VERSION=v1.9.0   # the govulncheck the gate requires; keep equal across the k3sm repos and the k3sm repository's hack/etcd-wrapper.sh

echo "==> [darwin-net] gofmt"
fmt=$(gofmt -l .) || true
[ -z "$fmt" ] || { echo "gofmt -w needed:"; echo "$fmt"; exit 1; }

echo "==> [darwin-net] license headers"
hack/verify-boilerplate.sh

# Enumerate the Go packages BEFORE deciding to skip anything. Exit 0 with empty
# output means "no Go packages yet" — the legitimate skip this guard was written
# for. A NON-ZERO exit (broken go.mod, unresolvable dependency, bad GOWORK, absent
# toolchain) is a HARD ERROR: the old `[ -n "$(go list ./... 2>/dev/null)" ]` could
# not tell the two apart, so it silently skipped vet/build/test and still reported
# green — a gate that cannot even enumerate its packages must go RED.
ci_tmp="$(mktemp -d)"
trap 'rm -rf "$ci_tmp"' EXIT
golist_err="$ci_tmp/golist.err"
if ! go_pkgs="$(CGO_ENABLED=$CGO go list ./... 2>"$golist_err")"; then
	echo "FAIL: [darwin-net] go list ./... failed — cannot enumerate packages; refusing to skip vet/build/test:" >&2
	cat "$golist_err" >&2
	exit 1
fi

if [ -n "$go_pkgs" ]; then
	echo "==> [darwin-net] go vet";   CGO_ENABLED=$CGO go vet ./...
	echo "==> [darwin-net] go build"; CGO_ENABLED=$CGO go build ./...
	# Every test runs under the race detector, as a go test -json stream piped
	# through hack/lib/testresults.go, which validates hack/quarantine.txt and applies
	# it for the tier. It echoes the output a plain go test prints and ends with the
	# failing tests. Its exit status says whether go test itself should have failed
	# (0: no failure, 3: only registry-excused failures), so the two statuses are
	# checked against each other: neither can turn the other green.
	echo "==> [darwin-net] go test -race (quarantine tier: $test_tier)"
	CGO_ENABLED=$CGO go build -o "$ci_tmp/testresults" hack/lib/testresults.go
	set +e
	CGO_ENABLED=$CGO go test -race -count=1 -json ./... 2>"$ci_tmp/gotest.err" \
		| "$ci_tmp/testresults" -registry hack/quarantine.txt -tier "$test_tier" ${edited_pkgs[@]+"${edited_pkgs[@]}"}
	st=("${PIPESTATUS[@]}")
	set -e
	go_rc="${st[0]}" tr_rc="${st[1]}"
	if [ -s "$ci_tmp/gotest.err" ]; then
		echo "==> [darwin-net] go test stderr:" >&2
		cat "$ci_tmp/gotest.err" >&2
	fi
	case "$go_rc:$tr_rc" in
		0:0) ;;
		1:3) echo "==> [darwin-net] go test failed only on quarantined tests (see QUARANTINED above)" ;;
		*:1) echo "==> [darwin-net] test stage RED (go test exit $go_rc); the RED lines above say why" >&2; exit 1 ;;
		*:0) echo "FAIL: [darwin-net] go test exited $go_rc but its stream holds no failure; read the stderr above" >&2; exit 1 ;;
		*) echo "FAIL: [darwin-net] go test exit $go_rc and testresults exit $tr_rc disagree" >&2; exit 1 ;;
	esac

	# The race witness: a planted race that go test -race must catch. If the
	# toolchain's race detector is not live, this goes red instead of the gate
	# passing races silently.
	echo "==> [darwin-net] race witness"
	if CGO_ENABLED=$CGO go test -race -count=1 ./hack/testdata/racewitness > "$ci_tmp/witness.log" 2>&1; then
		echo "FAIL: [darwin-net] the planted race in hack/testdata/racewitness passed; go test -race does not detect races" >&2
		exit 1
	fi
	if ! grep -q 'WARNING: DATA RACE' "$ci_tmp/witness.log"; then
		echo "FAIL: [darwin-net] the race witness failed without a race report:" >&2
		cat "$ci_tmp/witness.log" >&2
		exit 1
	fi

	# The getaddrinfo shim build tests skip without an x86_64-capable clang, and a
	# skip is invisible in the run above; on a host that can run them, they must pass.
	echo "==> [darwin-net] shim build tests ran"
	hack/verify-shim-not-skipped.sh

	# Wall-clock waits and fixed ports in tests, outside hack/test-sleeps.allow.
	echo "==> [darwin-net] test-sleep lint"
	hack/verify-test-sleeps.sh --self-test
	hack/verify-test-sleeps.sh
	# The integration-tagged tests (root, a real utun, a live datapath) never RUN here,
	# but they must still COMPILE: a signature drift in a tagged file would otherwise
	# go unnoticed until the next hand run. vet type-checks them; -run '^$' builds and
	# links every test binary under the tag and selects no test.
	echo "==> [darwin-net] go vet -tags integration";  CGO_ENABLED=$CGO go vet -tags integration ./...
	echo "==> [darwin-net] go test -tags integration (compile only)"; CGO_ENABLED=$CGO go test -tags integration -count=1 -run '^$' ./...
	# A root check in an integration-tagged test routes through k3smtest.SkipUnless
	# (k3sm.io/apis), so K3SM_CI_REQUIRE=root turns an absent root into a failure
	# instead of a silent skip. A hand-rolled os.Geteuid() gate reintroduces the
	# silent skip, so a match is RED, never a skip.
	echo "==> [darwin-net] integration-tagged tests: root checks go through k3smtest"
	raw_root=$(grep -rl --include='*_test.go' '^//go:build integration' pkg | xargs grep -n 'Geteuid' || true)
	if [ -n "$raw_root" ]; then
		echo "FAIL: [darwin-net] raw root check in an integration-tagged test; use k3smtest.SkipUnless(t, k3smtest.Root):" >&2
		echo "$raw_root" >&2
		exit 1
	fi

	# staticcheck, non-test code only. The test files are out of scope until a
	# separate sweep covers them, so the run passes -tests=false. A finding is
	# silenced only with `//lint:ignore <Check> <reason>` on the preceding line
	# (`//nolint` is golangci-lint's spelling and is inert here). The version is
	# exact on purpose: a different staticcheck reports different findings, so
	# the verdict would otherwise depend on the host. Bump STATICCHECK_VERSION
	# together with the Go toolchain and docs/GO-STANDARDS.md, and keep it in
	# step with the other k3sm repos. It runs after vet/build/test so a
	# mismatched host tool never stops those from running. Candidates, in order:
	# $(go env GOPATH)/bin/staticcheck-<pin> (the versioned name, so two pins can
	# be installed side by side while the repos switch), then staticcheck on PATH,
	# then $(go env GOPATH)/bin/staticcheck; the first reporting the pin wins.
	sc=""; sc_seen=""
	sc_cands=()
	sc_gopath="$(go env GOPATH)"
	sc_hint="go install honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}; or, beside another pin: GOBIN=<tmp> go install honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION} && mv <tmp>/staticcheck ${sc_gopath}/bin/staticcheck-${STATICCHECK_VERSION}"
	sc_versioned="${sc_gopath}/bin/staticcheck-${STATICCHECK_VERSION}"
	[ -x "$sc_versioned" ] && sc_cands+=("$sc_versioned")
	if sc_path="$(command -v staticcheck 2>/dev/null)" && [ -n "$sc_path" ]; then
		sc_cands+=("$sc_path")
	fi
	sc_gobin="${sc_gopath}/bin/staticcheck"
	[ -x "$sc_gobin" ] && sc_cands+=("$sc_gobin")
	for c in ${sc_cands[@]+"${sc_cands[@]}"}; do
		sc_out="$("$c" -version 2>/dev/null)" || true
		sc_ver="$(printf '%s\n' "$sc_out" | awk '{print $2}')"
		sc_seen="$sc_seen  $c reports '${sc_out:-no version output}'"$'\n'
		if [ "$sc_ver" = "$STATICCHECK_VERSION" ]; then sc="$c"; break; fi
	done
	if [ -z "$sc" ]; then
		if [ ${#sc_cands[@]} -eq 0 ]; then
			echo "==> [darwin-net] staticcheck: not installed; the gate needs ${STATICCHECK_VERSION} (${sc_hint})" >&2
		else
			echo "==> [darwin-net] staticcheck: the gate needs ${STATICCHECK_VERSION}, found:" >&2
			printf '%s' "$sc_seen" >&2
			echo "    install: ${sc_hint}" >&2
		fi
		exit 1
	fi
	echo "==> [darwin-net] staticcheck ${STATICCHECK_VERSION} (non-test)"; CGO_ENABLED=$CGO "$sc" -tests=false ./...
else
	echo "==> [darwin-net] (no Go packages yet — skipping vet/build/test)"
fi

echo "==> [darwin-net] go mod tidy (no-diff)"
go mod tidy
if [ -n "$(git status --porcelain -- go.mod go.sum 2>/dev/null)" ]; then
	echo "go.mod/go.sum not tidy after 'go mod tidy':"; git --no-pager diff -- go.mod go.sum; exit 1
fi

# The dependency supply-chain check (hack/verify-deps.sh): the go environment
# cannot weaken verification, go mod verify, the hack/deps.lock module graph,
# the 14-day cooldown on new versions, the OSV malicious-package query, go.mod
# replace discipline, and exact pins on every remote go install / go run. It
# needs proxy.golang.org and api.osv.dev; there is no offline skip, because a
# network failure there is RED by design. It runs only in the real module: the
# k3sm repository's hack/acceptance/ci_guard_test.go runs this script in a throwaway
# module whose graph the lock could never describe.
if grep -qx "module k3sm.io/darwin-net" go.mod 2>/dev/null; then
	echo "==> [darwin-net] verify-deps (self-test)"
	hack/verify-deps.sh --self-test
	echo "==> [darwin-net] verify-deps"
	hack/verify-deps.sh

	# govulncheck, pinned to an exact version like staticcheck: a different release
	# can report different findings. Each candidate (PATH first, then
	# $(go env GOPATH)/bin) is probed and the first reporting exactly the pin is
	# used. A missing or mismatched tool is RED, never a skip, and so is a finding
	# or a failure to reach the vulnerability database.
	gv=""; gv_seen=""
	for c in "$(command -v govulncheck 2>/dev/null || true)" "$(go env GOPATH)/bin/govulncheck"; do
		[ -n "$c" ] && [ -x "$c" ] || continue
		gv_ver="$("$c" -version 2>/dev/null | sed -n 's/^Scanner: govulncheck@//p' | head -1)" || gv_ver=""
		gv_seen="${gv_seen}    $c reports ${gv_ver:-no version}"$'\n'
		if [ "$gv_ver" = "$GOVULNCHECK_VERSION" ]; then gv="$c"; break; fi
	done
	if [ -z "$gv" ]; then
		if [ -z "$gv_seen" ]; then
			echo "==> [darwin-net] govulncheck: not installed; the gate needs ${GOVULNCHECK_VERSION} (go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION})" >&2
		else
			echo "==> [darwin-net] govulncheck: wrong version; the gate needs ${GOVULNCHECK_VERSION} (go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}). Found:" >&2
			printf '%s' "$gv_seen" >&2
		fi
		exit 1
	fi
	echo "==> [darwin-net] govulncheck ${GOVULNCHECK_VERSION} ./..."
	GOWORK=off CGO_ENABLED=$CGO "$gv" ./...
fi

echo "OK: darwin-net ci green"
