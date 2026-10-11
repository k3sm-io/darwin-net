#!/usr/bin/env bash
# darwin-net local CI — the docs/GO-STANDARDS.md commit gate in one command.
# The standard CI / pre-commit gate for this repo. Run from anywhere.
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

CGO=0   # darwin-net is pure Go (utun/pf/lo0 via golang.org/x/sys/unix)
STATICCHECK_VERSION=2026.2.1   # keep equal to the install pin in docs/GO-STANDARDS.md §Commit gates
GOVULNCHECK_VERSION=v1.8.0   # the govulncheck the gate requires; keep equal across the k3sm repos and hack/etcd-wrapper.sh

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
# green — a gate that cannot even enumerate its packages must go RED (B168).
golist_err="$(mktemp)"
trap 'rm -f "$golist_err"' EXIT
if ! go_pkgs="$(CGO_ENABLED=$CGO go list ./... 2>"$golist_err")"; then
	echo "FAIL: [darwin-net] go list ./... failed — cannot enumerate packages; refusing to skip vet/build/test:" >&2
	cat "$golist_err" >&2
	exit 1
fi

if [ -n "$go_pkgs" ]; then
	echo "==> [darwin-net] go vet";   CGO_ENABLED=$CGO go vet ./...
	echo "==> [darwin-net] go build"; CGO_ENABLED=$CGO go build ./...
	echo "==> [darwin-net] go test";  CGO_ENABLED=$CGO go test ./...
	# The integration-tagged tests (root, a real utun, a live datapath) never RUN here,
	# but they must still COMPILE: a signature drift in a tagged file would otherwise
	# go unnoticed until the next hand run. vet type-checks them; -run '^$' builds and
	# links every test binary under the tag and selects no test.
	echo "==> [darwin-net] go vet -tags integration";  CGO_ENABLED=$CGO go vet -tags integration ./...
	echo "==> [darwin-net] go test -tags integration (compile only)"; CGO_ENABLED=$CGO go test -tags integration -count=1 -run '^$' ./...

	# staticcheck, non-test code only. The test files are out of scope until a
	# separate sweep covers them, so the run passes -tests=false. A finding is
	# silenced only with `//lint:ignore <Check> <reason>` on the preceding line
	# (`//nolint` is golangci-lint's spelling and is inert here). The version is
	# exact on purpose: a different staticcheck reports different findings, so
	# the verdict would otherwise depend on the host. Bump STATICCHECK_VERSION
	# together with the Go toolchain and docs/GO-STANDARDS.md, and keep it in
	# step with the other k3sm repos. It runs after vet/build/test so a
	# mismatched host tool never stops those from running.
	sc=""; sc_seen=""
	sc_cands=()
	if sc_path="$(command -v staticcheck 2>/dev/null)" && [ -n "$sc_path" ]; then
		sc_cands+=("$sc_path")
	fi
	sc_gobin="$(go env GOPATH)/bin/staticcheck"
	[ -x "$sc_gobin" ] && sc_cands+=("$sc_gobin")
	for c in ${sc_cands[@]+"${sc_cands[@]}"}; do
		sc_out="$("$c" -version 2>/dev/null)" || true
		sc_ver="$(printf '%s\n' "$sc_out" | awk '{print $2}')"
		sc_seen="$sc_seen  $c reports '${sc_out:-no version output}'"$'\n'
		if [ "$sc_ver" = "$STATICCHECK_VERSION" ]; then sc="$c"; break; fi
	done
	if [ -z "$sc" ]; then
		if [ ${#sc_cands[@]} -eq 0 ]; then
			echo "==> [darwin-net] staticcheck: not installed; the gate needs ${STATICCHECK_VERSION} (go install honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION})" >&2
		else
			echo "==> [darwin-net] staticcheck: the gate needs ${STATICCHECK_VERSION}, found:" >&2
			printf '%s' "$sc_seen" >&2
			echo "    install: go install honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}" >&2
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
# k3sm repo's hack/acceptance/ci_guard_test.go runs this script in a throwaway
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
