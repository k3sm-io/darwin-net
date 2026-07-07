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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// genCert mints an in-memory self-signed certificate for host and returns it
// parsed plus its PEM bytes (for the ParseKeyPair leg). Nothing touches disk.
func genCert(t *testing.T, host string) (*tls.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := ParseKeyPair("test-secret", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("ParseKeyPair: %v", err)
	}
	return cert, certPEM, keyPEM
}

// handshake dials the TLS listener with sni and returns the handshake error
// and, on success, the served leaf certificate's DNS names.
func handshake(t *testing.T, addr, sni string) ([]string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d := &tls.Dialer{Config: &tls.Config{
		ServerName: sni,
		// The test asserts WHICH certificate was served (below), so chain
		// verification against a system pool is deliberately skipped.
		InsecureSkipVerify: true,
	}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, nil
	}
	return state.PeerCertificates[0].DNSNames, nil
}

// TestIngressTLSSNIPerHostIsolation is the M10.3 TLS gate: SNI selects the
// per-host certificate; a host whose Secret failed to parse is simply absent
// and fails ONLY its own handshakes; an unknown (or empty) SNI closes the
// handshake — no default certificate is invented; and a certificate-map swap
// takes effect atomically for new handshakes. It also pins the ParseKeyPair
// error discipline: the error names the SECRET, never the key bytes.
func TestIngressTLSSNIPerHostIsolation(t *testing.T) {
	store := NewCertStore()
	certA, _, _ := genCert(t, "a.example.com")
	_, certBPEM, keyBPEM := genCert(t, "b.example.com")

	// b.example.com's Secret is malformed: ParseKeyPair fails naming the secret
	// and echoing none of the (attacker-controlled) bytes, so the host simply
	// never installs b — per-host isolation, not a serving-wide failure.
	garbageKey := []byte("-----BEGIN EC PRIVATE KEY-----\nZ2FyYmFnZS1rZXktYnl0ZXM=\n-----END EC PRIVATE KEY-----\n")
	if _, err := ParseKeyPair("b-tls-secret", certBPEM, garbageKey); err == nil {
		t.Fatal("ParseKeyPair accepted a garbage key")
	} else {
		msg := err.Error()
		if !strings.Contains(msg, "b-tls-secret") {
			t.Fatalf("parse error does not name the secret: %q", msg)
		}
		if strings.Contains(msg, "Z2FyYmFnZS1rZXktYnl0ZXM") {
			t.Fatalf("parse error leaked key bytes: %q", msg)
		}
	}
	store.SetCertificates(map[string]*tls.Certificate{"a.example.com": certA})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tln := tls.NewListener(ln, serverTLSConfig(store))
	defer tln.Close()
	go func() {
		for {
			c, err := tln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Drive the handshake; a GetCertificate miss fails just this
				// connection.
				_ = c.(*tls.Conn).HandshakeContext(context.Background())
			}(c)
		}
	}()
	addr := tln.Addr().String()

	t.Run("known SNI serves that host's certificate", func(t *testing.T) {
		names, err := handshake(t, addr, "a.example.com")
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		if len(names) != 1 || names[0] != "a.example.com" {
			t.Fatalf("served cert for %v, want a.example.com", names)
		}
	})
	t.Run("uninstalled host fails only its own handshake", func(t *testing.T) {
		if _, err := handshake(t, addr, "b.example.com"); err == nil {
			t.Fatal("handshake for uninstalled host succeeded")
		}
		if _, err := handshake(t, addr, "a.example.com"); err != nil {
			t.Fatalf("healthy host degraded by sibling's missing cert: %v", err)
		}
	})
	t.Run("no SNI closes the handshake (no default cert)", func(t *testing.T) {
		if _, err := handshake(t, addr, ""); err == nil {
			t.Fatal("handshake without SNI succeeded")
		}
	})
	t.Run("certificate swap serves the new host atomically", func(t *testing.T) {
		goodB, err := ParseKeyPair("b-tls-secret", certBPEM, keyBPEM)
		if err != nil {
			t.Fatalf("ParseKeyPair: %v", err)
		}
		store.SetCertificates(map[string]*tls.Certificate{
			"a.example.com": certA,
			"B.Example.Com": goodB, // key normalization: stored lowercase
		})
		names, err := handshake(t, addr, "b.example.com")
		if err != nil {
			t.Fatalf("handshake after swap: %v", err)
		}
		if len(names) != 1 || names[0] != "b.example.com" {
			t.Fatalf("served cert for %v, want b.example.com", names)
		}
	})
}
