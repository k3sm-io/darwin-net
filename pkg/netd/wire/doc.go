/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package wire is the versioned, length-prefixed RPC contract between the
// unprivileged k3sm processes (the pod network, the Service proxy, the wireguard
// mesh controller) and the root k3sm-netd daemon (k3sm.io/darwin-net/pkg/netd).
//
// It is a deliberately small, auditable leaf package: it imports nothing from
// k3sm.io/* so both the daemon (which also imports pkg/podnet and pkg/mesh to
// re-validate every request) and its clients (pkg/podnet, pkg/proxy, pkg/mesh) can
// depend on it without an import cycle.
//
// # Framing
//
// Each message is a 4-byte big-endian length prefix followed by a JSON payload,
// bounded by a per-read cap (DefaultMaxRequestBytes) so a hostile or corrupt
// length can never drive an unbounded allocation. Every Request carries a Version;
// the daemon rejects an incompatible MAJOR skew and accepts any (additive) MINOR.
//
// # Closed verb set, typed scalars only
//
// The protocol never carries route/pf/wireguard-UAPI text. Each Request names one
// Verb from a closed set and carries only typed scalars (an IP, a port, a typed
// peer list). The daemon re-derives and re-validates every parameter and RENDERS
// the privileged artifacts (UAPI, pf rules) itself. The only file descriptor that
// ever crosses the socket is the listening socket BindPort returns to the client
// via SCM_RIGHTS; the protocol accepts no inbound fd and no filesystem path.
package wire
