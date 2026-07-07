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

package ingress

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
)

// ErrNoCertificate is returned by the TLS GetCertificate callback when no
// certificate is installed for the requested SNI host. It fails ONLY that
// handshake — per-host isolation: a missing or bad certificate for one host
// never degrades another host's TLS service, and no default certificate is
// invented for an unknown SNI.
var ErrNoCertificate = errors.New("ingress: no certificate for sni host")

// CertResolver resolves the TLS certificate serving a host. It is the
// consumer-defined seam between the ingress and whoever owns Secret material:
// the host process watches the referenced tls[] Secrets (surfaced by the
// Watcher's OnTLSSecrets callback) and installs parsed certificates — this
// package never holds a Secrets client and never sees Secret storage.
type CertResolver interface {
	// Certificate returns the certificate for the lowercase SNI host, if any.
	Certificate(host string) (*tls.Certificate, bool)
}

// CertStore is the default CertResolver: an atomically-swapped SNI-host ->
// certificate map. Certificates and their private keys live IN PROCESS MEMORY
// ONLY — nothing here ever touches a filesystem path, so key material is never
// exposed under the shared _k3sm uid.
//
// Concurrency: SetCertificates replaces the whole map via atomic pointer swap
// (copying the input), so handshakes racing a Secret rotation see either the
// old or the new consistent map, never a torn one.
type CertStore struct {
	certs atomic.Pointer[map[string]*tls.Certificate]
}

// NewCertStore returns an empty store (every handshake fails until
// certificates are installed).
func NewCertStore() *CertStore {
	s := &CertStore{}
	empty := map[string]*tls.Certificate{}
	s.certs.Store(&empty)
	return s
}

// SetCertificates atomically replaces the store's contents. Host keys are
// normalized to lowercase; the map is copied so the caller cannot mutate the
// live snapshot. A host the caller failed to parse a certificate for is simply
// absent — its handshakes fail (per-host isolation), everyone else is served.
func (s *CertStore) SetCertificates(certs map[string]*tls.Certificate) {
	m := make(map[string]*tls.Certificate, len(certs))
	for host, c := range certs {
		m[strings.ToLower(host)] = c
	}
	s.certs.Store(&m)
}

// Certificate returns the certificate for host, if installed.
func (s *CertStore) Certificate(host string) (*tls.Certificate, bool) {
	m := *s.certs.Load()
	c, ok := m[host]
	return c, ok
}

// ParseKeyPair parses a PEM certificate/key pair from a tls[] Secret's bytes,
// entirely in memory. On failure the error carries the SECRET NAME only —
// never the certificate or key bytes (the stdlib tls.X509KeyPair error text is
// generic and echoes no input material) — so a malformed Secret can be logged
// without leaking what it held.
func ParseKeyPair(secretName string, certPEM, keyPEM []byte) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse tls secret %s: %w", secretName, err)
	}
	return &cert, nil
}

// serverTLSConfig builds the ingress TLS termination config over r: SNI-keyed
// certificate selection with per-host failure isolation (an unknown SNI or a
// host whose certificate failed to install closes only that handshake — no
// default certificate).
//
// NextProtos is DELIBERATELY pinned to http/1.1: h2 (and gRPC over it) through
// the L7 datapath is untested and therefore deferred — do not add "h2" here
// without an M10.3 follow-up that tests it end-to-end.
func serverTLSConfig(r CertResolver) *tls.Config {
	return &tls.Config{
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := strings.ToLower(hello.ServerName)
			if c, ok := r.Certificate(host); ok {
				return c, nil
			}
			return nil, fmt.Errorf("%w: %q", ErrNoCertificate, host)
		},
	}
}
