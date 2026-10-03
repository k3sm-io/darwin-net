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

package dns

import (
	"context"
	"net"
	"net/netip"
)

// withDialer overrides the UDP dialer; tests use it to reach a stub server.
func withDialer(d func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(r *Resolver) { r.dial = d }
}

// withServerAddrs replaces the resolver's per-server "ip:port" list, so a test
// can point each configured nameserver at its own stub — the Go analog of the
// shim's "ipv4:port" K3SM_DNS_SERVERS tokens. It must keep the server count the
// config implies for the walk to mean what the config says.
func withServerAddrs(addrs ...string) Option {
	return func(r *Resolver) { r.servers = addrs }
}

// withCandidateTrace installs the per-candidate seam LookupHost calls once for
// each candidate it queries, mirroring the shim's per-candidate debug line.
func withCandidateTrace(f func(cand string, addrs []netip.Addr, err error)) Option {
	return func(r *Resolver) { r.onCandidate = f }
}

// lookupCandidate resolves one FQDN on its own, with a fresh dead-server memo:
// the per-candidate altitude the drift guards and the wire differential read.
func (r *Resolver) lookupCandidate(ctx context.Context, fqdn string) ([]netip.Addr, error) {
	return r.queryCandidate(ctx, fqdn, make([]bool, len(r.servers)))
}
