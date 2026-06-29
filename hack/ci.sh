#!/usr/bin/env bash
# darwin-net local CI — the docs/GO-STANDARDS.md commit gate in one command.
# Exactly what a /orchestrate builder agent runs before checkpointing, and what the
# workspace hack/ci.sh invokes for this repo. Run from anywhere.
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

CGO=0   # darwin-net is pure Go (utun/pf/lo0 via golang.org/x/sys/unix)

echo "==> [darwin-net] gofmt"
fmt=$(gofmt -l .) || true
[ -z "$fmt" ] || { echo "gofmt -w needed:"; echo "$fmt"; exit 1; }

echo "==> [darwin-net] license headers"
hack/verify-boilerplate.sh

if [ -n "$(CGO_ENABLED=$CGO go list ./... 2>/dev/null)" ]; then
	echo "==> [darwin-net] go vet";   CGO_ENABLED=$CGO go vet ./...
	echo "==> [darwin-net] go build"; CGO_ENABLED=$CGO go build ./...
	echo "==> [darwin-net] go test";  CGO_ENABLED=$CGO go test ./...
else
	echo "==> [darwin-net] (no Go packages yet — skipping vet/build/test)"
fi

echo "==> [darwin-net] go mod tidy (no-diff)"
go mod tidy
if [ -n "$(git status --porcelain -- go.mod go.sum 2>/dev/null)" ]; then
	echo "go.mod/go.sum not tidy after 'go mod tidy':"; git --no-pager diff -- go.mod go.sum; exit 1
fi

echo "OK: darwin-net ci green"
