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

// Package netbind is the single home of the listener-bind privilege seam shared
// by darwin-net's socket-owning consumers (the L4 Service proxy in pkg/proxy and
// the L7 ingress in pkg/ingress).
//
// A Binder opens a listening socket on the address the CALLER chooses. An
// implementation may refuse an address it is not authorized to bind — Netd
// refuses the wildcard, which the root netd daemon rejects as a cross-tenant
// footgun on the shared node — so callers handle the error rather than assume a
// legal address by construction. Two implementations exist:
//
//   - Direct binds with net.Listen in-process: the explicit run-as-root mode and
//     the rootless-test mode.
//   - Netd asks the root netd daemon (VerbBindPort) to bind the port and adopts
//     the listening socket passed back over SCM_RIGHTS, so an unprivileged
//     consumer can serve a privileged (<1024) port it could not bind itself.
//
// This package exists so the SCM_RIGHTS fd-adoption path is written exactly once:
// pkg/proxy re-uses it (keeping its own >=1024-binds-locally transport
// optimization as a thin wrapper), and pkg/ingress routes every helper-mode bind
// through Netd unconditionally.
package netbind
