#!/usr/bin/env bash
# darwin-net local CI — the docs/GO-STANDARDS.md commit gate in one command.
# The standard CI / pre-commit gate for this repo. Run from anywhere.
#
#   hack/ci.sh [--tier fast|full] [--edited <file>]
#              [--affected <base-sha> | --packages <file> [--base <sha>]] [--dry-run]
#
# --tier picks how the test stage applies hack/quarantine.txt: full (the default)
# reds on every failing test; fast excuses a listed flake outside the packages the
# change edits. --edited names a file with one edited import path per line.
#
# With no mode flag the gate is the full gate, unchanged. Two explicit modes narrow
# only the go vet and go test package sets; every other stage still runs:
#   --packages <file>  read a k3sm-affected/v1 package list (the format the affected-set
#                      selector writes; its grammar is restated in read_packages below).
#                      A missing, unreadable, malformed or unknown-version file, or an
#                      @full line for darwin-net, runs the full gate. A list holding no darwin-net
#                      package is red when the diff against --base (default: the merge
#                      base with origin/main) holds a .go file, runs the full gate when it
#                      holds any other non-doc file (the gate cannot map it to a package)
#                      or the base does not resolve, and skips vet and test when only doc
#                      files (*.md, docs/, LICENSE, NOTICE, DCO) changed.
#   --affected <base>  compute the list with hack/affected.sh against <base>, then as
#                      --packages; a clone without that selector runs the full gate.
# --dry-run resolves the mode, prints the plan (mode, reason, vet and test sets) and
# exits before any stage runs: 0 for a plan, 1 for a red verdict.
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

usage() {
	echo "usage: hack/ci.sh [--tier fast|full] [--edited <file>] [--affected <base-sha> | --packages <file> [--base <sha>]] [--dry-run]" >&2
	exit 2
}
test_tier=full
edited_file=""
pkg_file="" pkg_file_set=0 affected_base="" diff_base="" dry_run=0
while [ $# -gt 0 ]; do
	case "$1" in
		--tier) [ $# -ge 2 ] || usage; test_tier="$2"; shift 2 ;;
		--edited) [ $# -ge 2 ] || usage; edited_file="$2"; shift 2 ;;
		--packages) [ $# -ge 2 ] || usage; pkg_file="$2"; pkg_file_set=1; shift 2 ;;
		--affected) [ $# -ge 2 ] && [ -n "$2" ] || usage; affected_base="$2"; shift 2 ;;
		--base) [ $# -ge 2 ] && [ -n "$2" ] || usage; diff_base="$2"; shift 2 ;;
		--dry-run) dry_run=1; shift ;;
		*) usage ;;
	esac
done
case "$test_tier" in fast|full) ;; *) echo "hack/ci.sh: --tier must be fast or full" >&2; exit 2 ;; esac
if [ "$pkg_file_set" = 1 ] && [ -n "$affected_base" ]; then
	echo "hack/ci.sh: --affected and --packages are exclusive" >&2; exit 2
fi
if [ -n "$diff_base" ] && [ "$pkg_file_set" = 0 ]; then
	echo "hack/ci.sh: --base goes with --packages (--affected takes its own base)" >&2; exit 2
fi
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

ci_tmp="$(mktemp -d)"
trap 'rm -rf "$ci_tmp"' EXIT

# read_packages <file>: the strict k3sm-affected/v1 reader. Line 1 is exactly
# k3sm-affected/v1; then sorted, unique import paths; then `@full <repo> <reason>`
# lines; then `@check <repo> <name> [<arg>]` lines with <name> from the closed set;
# the last line is exactly @end, followed by a final newline. No blank lines, no
# comments. Fields are separated by exactly one space, as the writer emits them,
# and the file is UTF-8 with no NUL byte. Any deviation sets pf_reason and returns 1
# (the caller runs full).
# On success: pf_pkgs (every package line), pf_full (the @full reason for darwin-net, or
# empty), pf_checks (the @check lines for darwin-net).
pf_pkgs=() pf_checks=() pf_full="" pf_reason=""
read_packages() {
	local f="$1" line n=0 phase=0 prev="" seen_end=0 name rest LC_ALL=C
	local -a w
	pf_pkgs=() pf_checks=() pf_full="" pf_reason=""
	[ -e "$f" ] || { pf_reason="$f does not exist"; return 1; }
	[ -f "$f" ] && [ -r "$f" ] || { pf_reason="$f is not a readable file"; return 1; }
	if [ ! -s "$f" ] || [ "$(tail -c 1 "$f" | od -An -c | tr -d ' ')" != '\n' ]; then
		pf_reason="$f is empty or does not end with a newline"; return 1
	fi
	# read drops a NUL byte and the line regexes never see an invalid byte in a
	# reason, so both are refused here, as the workspace reader refuses them.
	[ "$(tr -d '\000' < "$f" | wc -c)" -eq "$(wc -c < "$f")" ] || { pf_reason="$f holds a NUL byte"; return 1; }
	iconv -f UTF-8 -t UTF-8 "$f" >/dev/null 2>&1 || { pf_reason="$f is not UTF-8"; return 1; }
	while IFS= read -r line; do
		n=$((n + 1))
		[ "$seen_end" = 0 ] || { pf_reason="line $n: text after @end"; return 1; }
		if [ "$n" = 1 ]; then
			[ "$line" = "k3sm-affected/v1" ] || { pf_reason="line 1 is not k3sm-affected/v1"; return 1; }
			continue
		fi
		case "$line" in
			@end) seen_end=1 ;;
			"@full "*)
				[ "$phase" -le 1 ] || { pf_reason="line $n: @full after @check"; return 1; }
				phase=1
				# @full <repo> <reason>: the repo ends at the next single space, and the
				# reason is the rest, which must hold a non-space character.
				rest="${line#@full }" name="${rest%% *}"
				[ "$name" != "$rest" ] && [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] && [[ "${rest#* }" =~ [^[:space:]] ]] \
					|| { pf_reason="line $n: bad @full"; return 1; }
				if [ "$name" = darwin-net ]; then pf_full="${rest#* }"; fi
				;;
			"@check "*)
				phase=2
				# @check <repo> <name> [<arg>]: split on every single space, keeping empty
				# fields, so a doubled space or a tab is refused, not collapsed.
				rest="${line#@check }" w=()
				while :; do
					case "$rest" in
						*" "*) w+=("${rest%% *}"); rest="${rest#* }" ;;
						*) w+=("$rest"); break ;;
					esac
				done
				{ [ ${#w[@]} = 2 ] || [ ${#w[@]} = 3 ]; } && [[ "${w[0]}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { pf_reason="line $n: bad @check"; return 1; }
				name="${w[1]}"
				case "$name" in buf|verify-deps|govulncheck|tidy|gofmt|boilerplate|vet-tags|script) ;; *) pf_reason="line $n: unknown @check $name"; return 1 ;; esac
				if [ "${w[0]}" = darwin-net ]; then pf_checks+=("${line#@check darwin-net }"); fi
				;;
			*)
				[[ "$line" =~ ^[A-Za-z0-9][A-Za-z0-9._~/-]*$ ]] || { pf_reason="line $n: unrecognised line"; return 1; }
				[ "$phase" = 0 ] || { pf_reason="line $n: package after a keyed line"; return 1; }
				if [ -n "$prev" ] && ! [[ "$prev" < "$line" ]]; then pf_reason="line $n: packages are not sorted and unique"; return 1; fi
				prev="$line"
				pf_pkgs+=("$line")
				;;
		esac
	done < "$f"
	[ "$seen_end" = 1 ] || { pf_reason="missing @end (truncated?)"; return 1; }
	return 0
}

# Mode resolution. vet_set and test_set default to the full gate; only an explicit
# mode flag with a valid list narrows them, and every doubt answers full.
mode=full mode_reason="no mode flag (the default)"
vet_set=(./...) test_set=(./...)
if [ -n "$affected_base" ]; then
	if [ -x hack/affected.sh ] && hack/affected.sh select --repo "darwin-net=.@$affected_base" --gowork off --format packages > "$ci_tmp/affected.txt" 2>"$ci_tmp/affected.err"; then
		pkg_file="$ci_tmp/affected.txt" pkg_file_set=1 diff_base="$affected_base"
	elif [ -x hack/affected.sh ]; then
		mode_reason="--affected: the selector failed ($(head -1 "$ci_tmp/affected.err")); full gate"
	else
		mode_reason="--affected: this clone has no hack/affected.sh selector; full gate"
	fi
fi
if [ "$pkg_file_set" = 1 ]; then
	module="$(awk '$1 == "module" { print $2; exit }' go.mod)"
	if ! read_packages "$pkg_file"; then
		mode_reason="--packages: $pf_reason; full gate"
	elif [ -n "$pf_full" ]; then
		mode_reason="--packages: @full darwin-net $pf_full"
	else
		own=()
		for p in ${pf_pkgs[@]+"${pf_pkgs[@]}"}; do
			case "$p" in "$module"|"$module"/*) own+=("$p") ;; esac
		done
		if [ ${#own[@]} -gt 0 ]; then
			mode=packages mode_reason="--packages: ${#own[@]} $module package(s) from $pkg_file"
			vet_set=("${own[@]}") test_set=("${own[@]}")
		else
			# An empty selection is legitimate only when the change holds no Go file.
			base="$diff_base"
			[ -n "$base" ] || base="$(git merge-base HEAD origin/main 2>/dev/null || true)"
			if [ -z "$base" ] || ! git rev-parse -q --verify "$base^{commit}" >/dev/null 2>&1; then
				mode_reason="--packages: no $module package listed and the diff base does not resolve; full gate"
			elif changed="$( { git diff --name-only "$base" -- && git ls-files --others --exclude-standard; } 2>"$ci_tmp/diff.err")"; then
				if printf '%s\n' "$changed" | grep -q '\.go$'; then
					echo "FAIL: [darwin-net] --packages lists no $module package, but the diff against $base holds Go changes:" >&2
					printf '%s\n' "$changed" | grep '\.go$' | sed 's/^/    /' >&2
					echo "    the selector cannot legitimately answer that; refusing a silent green" >&2
					exit 1
				fi
				# Only a doc file is known to reach no package. Any other change (a cgo or
				# assembly source, an embed asset, testdata, go.mod, go.sum) can, and an
				# empty list cannot say which, so it runs the full gate.
				unmapped="$(printf '%s\n' "$changed" | grep -v -e '^$' -e '\.md$' -e '^docs/' -e '^LICENSE$' -e '^NOTICE$' -e '^DCO$' || true)"
				if [ -n "$unmapped" ]; then
					mode_reason="--packages: no $module package listed and the diff against $base changes a non-doc file the gate cannot map ($(printf '%s\n' "$unmapped" | head -1)); full gate"
				else
					mode=packages mode_reason="--packages: no $module package listed and only doc files changed against $base; vet and test skipped"
					vet_set=() test_set=()
				fi
			else
				mode_reason="--packages: git diff against $base failed; full gate"
			fi
		fi
		for c in ${pf_checks[@]+"${pf_checks[@]}"}; do echo "==> [darwin-net] keyed check owed: $c (its stage runs in every mode)"; done
	fi
fi
if [ "$pkg_file_set" = 1 ] || [ -n "$affected_base" ]; then
	echo "==> [darwin-net] gate mode: $mode ($mode_reason)"
fi
if [ "$dry_run" = 1 ]; then
	echo "mode: $mode"
	echo "reason: $mode_reason"
	echo "vet: ${vet_set[*]+${vet_set[*]}}"
	echo "test: ${test_set[*]+${test_set[*]}}"
	exit 0
fi

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
golist_err="$ci_tmp/golist.err"
if ! go_pkgs="$(CGO_ENABLED=$CGO go list ./... 2>"$golist_err")"; then
	echo "FAIL: [darwin-net] go list ./... failed — cannot enumerate packages; refusing to skip vet/build/test:" >&2
	cat "$golist_err" >&2
	exit 1
fi

if [ -n "$go_pkgs" ]; then
	if [ ${#vet_set[@]} -gt 0 ]; then
		echo "==> [darwin-net] go vet";   CGO_ENABLED=$CGO go vet "${vet_set[@]}"
	else
		echo "==> [darwin-net] go vet: skipped (no affected package)"
	fi
	echo "==> [darwin-net] go build"; CGO_ENABLED=$CGO go build ./...
	# Every test runs under the race detector, as a go test -json stream piped
	# through hack/lib/testresults.go, which validates hack/quarantine.txt and applies
	# it for the tier. It echoes the output a plain go test prints and ends with the
	# failing tests. Its exit status says whether go test itself should have failed
	# (0: no failure, 3: only registry-excused failures), so the two statuses are
	# checked against each other: neither can turn the other green.
	if [ ${#test_set[@]} -gt 0 ]; then
		echo "==> [darwin-net] go test -race (quarantine tier: $test_tier)"
		CGO_ENABLED=$CGO go build -o "$ci_tmp/testresults" hack/lib/testresults.go
		set +e
		CGO_ENABLED=$CGO go test -race -count=1 -json "${test_set[@]}" 2>"$ci_tmp/gotest.err" \
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
	else
		echo "==> [darwin-net] go test: skipped (no affected package)"
	fi

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
