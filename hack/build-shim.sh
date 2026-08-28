#!/usr/bin/env bash
# Build the k3sm getaddrinfo DYLD interpose shim.
#
# The shim is a plain C dylib (NOT Go cgo) so darwin-net's Go stays
# CGO_ENABLED=0; a DYLD interposer must be a C dylib with a __DATA,__interpose
# section regardless. Loaded into a pod via DYLD_INSERT_LIBRARIES, it routes
# getaddrinfo() to CoreDNS over the cluster DNS VIP (macOS getaddrinfo ignores
# /etc/resolv.conf — see DESIGN §3).
#
# Usage:
#   hack/build-shim.sh [output-dir]
# Output:
#   <output-dir>/libk3sm_getaddrinfo_shim.dylib   (default output-dir: build/)
set -euo pipefail

cd "$(dirname "$0")/.."   # repo root

SRC="shim/getaddrinfo_shim.c"
OUT_DIR="${1:-build}"
OUT="${OUT_DIR}/libk3sm_getaddrinfo_shim.dylib"

mkdir -p "$OUT_DIR"

# arm64 + x86_64 universal (fat) dylib so it loads regardless of the pod binary's
# arch: dyld HARD-TERMINATES a process whose DYLD_INSERT_LIBRARIES library lacks a
# slice for that process's architecture, so an arm64-only shim would kill a
# darwin/amd64 pod payload running under Rosetta rather than merely skip DNS.
# Asserted on the built Mach-O by pkg/dns TestShimIsUniversalBinary -- assert the
# ARTIFACT, never these flags, since the flags are what drifted from this comment.
# -fPIC and -dynamiclib for a shared library; -install_name keeps it relocatable.
clang \
  -arch arm64 \
  -arch x86_64 \
  -dynamiclib \
  -fPIC \
  -O2 \
  -Wall -Wextra \
  -install_name "@rpath/$(basename "$OUT")" \
  -o "$OUT" \
  "$SRC"

echo "built $OUT"
