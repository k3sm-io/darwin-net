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
	"log/slog"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// waitFor polls cond until it holds or the deadline elapses.
func waitFor(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

func className(s string) *string { return &s }

func pathTypePtr(pt networkingv1.PathType) *networkingv1.PathType { return &pt }

// testIngress builds a one-rule Ingress referencing service web's named port.
func testIngress(name, class, host string, backend networkingv1.IngressServiceBackend, tlsSecret string) *networkingv1.Ingress {
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{
				Host: host,
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							Path:     "/app",
							PathType: pathTypePtr(networkingv1.PathTypePrefix),
							Backend:  networkingv1.IngressBackend{Service: &backend},
						}},
					},
				},
			}},
		},
	}
	if class != "" {
		ing.Spec.IngressClassName = className(class)
	}
	if tlsSecret != "" {
		ing.Spec.TLS = []networkingv1.IngressTLS{{Hosts: []string{host}, SecretName: tlsSecret}}
	}
	return ing
}

// TestIngressClassFilteredWatch is the M10.3 watcher gate: only the Ingress
// whose spec.ingressClassName matches Config.ClassName reconciles (a foreign
// class and a nil class are ignored); the backend's named Service port
// resolves through the Services store to the ClusterIP VIP + port number; and
// the tls[] Secret references surface to the host via the callback (this
// package never fetches Secrets itself).
func TestIngressClassFilteredWatch(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.43.1.5",
			Ports:     []corev1.ServicePort{{Name: "http", Port: 8080}},
		},
	}
	byName := networkingv1.IngressServiceBackend{
		Name: "web",
		Port: networkingv1.ServiceBackendPort{Name: "http"}, // port-by-NAME: needs the Service object
	}
	byNumber := networkingv1.IngressServiceBackend{
		Name: "web",
		Port: networkingv1.ServiceBackendPort{Number: 8080},
	}
	client := fake.NewClientset(
		svc,
		testIngress("mine", "k3sm", "a.example.com", byName, "web-tls"),
		testIngress("foreign-class", "nginx", "b.example.com", byNumber, ""),
		testIngress("classless", "", "c.example.com", byNumber, ""),
	)

	var (
		refMu   sync.Mutex
		tlsRefs []SecretRef
	)
	table := NewRouteTable()
	w := NewWatcher(client, table, WatcherConfig{
		ClassName: "k3sm",
		OnTLSSecrets: func(refs []SecretRef) {
			refMu.Lock()
			tlsRefs = refs
			refMu.Unlock()
		},
	}, slog.New(slog.DiscardHandler))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = w.Run(ctx) }()

	wantBackend := Backend{VIP: netip.MustParseAddr("10.43.1.5"), Port: 8080}
	waitFor(t, 3*time.Second, func() bool {
		got, ok := table.Match("a.example.com", "/app/x")
		return ok && got == wantBackend
	}, "matching-class Ingress did not reconcile (named Service port -> VIP:8080)")

	if _, ok := table.Match("b.example.com", "/app"); ok {
		t.Error("foreign-class Ingress reconciled; the watcher must reconcile only its class")
	}
	if _, ok := table.Match("c.example.com", "/app"); ok {
		t.Error("classless (nil ingressClassName) Ingress reconciled")
	}

	wantRefs := []SecretRef{{Namespace: "default", Name: "web-tls", Hosts: []string{"a.example.com"}}}
	waitFor(t, 3*time.Second, func() bool {
		refMu.Lock()
		defer refMu.Unlock()
		return reflect.DeepEqual(tlsRefs, wantRefs)
	}, "tls[] secret reference did not surface via OnTLSSecrets")

	cancel()
	<-runDone
}
