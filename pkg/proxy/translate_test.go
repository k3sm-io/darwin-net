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

package proxy

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	netv1 "k3sm.io/apis/net/v1"
)

func ptrBool(b bool) *bool                        { return &b }
func ptrStr(s string) *string                     { return &s }
func ptrInt32(i int32) *int32                     { return &i }
func ptrProto(p corev1.Protocol) *corev1.Protocol { return &p }

// TestServiceToVIP asserts the pure Service translator: ClusterIP services map to
// a netv1.ServiceVIP; headless / ExternalName / portless services are not served.
func TestServiceToVIP(t *testing.T) {
	t.Parallel()

	mk := func(typ corev1.ServiceType, cip string, ports ...corev1.ServicePort) *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"},
			Spec:       corev1.ServiceSpec{Type: typ, ClusterIP: cip, Ports: ports},
		}
	}
	httpPort := corev1.ServicePort{Name: "http", Port: 80, TargetPort: intstr.FromInt32(8080), Protocol: corev1.ProtocolTCP, NodePort: 30080}

	cases := []struct {
		name    string
		svc     *corev1.Service
		wantOK  bool
		wantVIP netv1.ServiceVIP
	}{
		{
			name:   "clusterip tcp service",
			svc:    mk(corev1.ServiceTypeClusterIP, "10.43.0.10", httpPort),
			wantOK: true,
			wantVIP: netv1.ServiceVIP{
				Namespace: "default", Name: "web", ClusterIP: "10.43.0.10",
				Ports: []netv1.ServicePort{{Name: "http", Port: 80, TargetPort: 8080, Protocol: netv1.ProtocolTCP, NodePort: 30080}},
			},
		},
		{
			name:   "empty protocol defaults to TCP",
			svc:    mk(corev1.ServiceTypeClusterIP, "10.43.0.10", corev1.ServicePort{Port: 80, TargetPort: intstr.FromInt32(8080)}),
			wantOK: true,
			wantVIP: netv1.ServiceVIP{
				Namespace: "default", Name: "web", ClusterIP: "10.43.0.10",
				Ports: []netv1.ServicePort{{Port: 80, TargetPort: 8080, Protocol: netv1.ProtocolTCP}},
			},
		},
		{
			name:   "headless (ClusterIP None) not served",
			svc:    mk(corev1.ServiceTypeClusterIP, corev1.ClusterIPNone, httpPort),
			wantOK: false,
		},
		{
			name:   "empty ClusterIP not served",
			svc:    mk(corev1.ServiceTypeClusterIP, "", httpPort),
			wantOK: false,
		},
		{
			name:   "ExternalName not served",
			svc:    mk(corev1.ServiceTypeExternalName, "10.43.0.10", httpPort),
			wantOK: false,
		},
		{
			name:   "no ports not served",
			svc:    mk(corev1.ServiceTypeClusterIP, "10.43.0.10"),
			wantOK: false,
		},
		{
			name:   "SCTP-only port dropped leaves no ports",
			svc:    mk(corev1.ServiceTypeClusterIP, "10.43.0.10", corev1.ServicePort{Port: 80, TargetPort: intstr.FromInt32(8080), Protocol: corev1.ProtocolSCTP}),
			wantOK: false,
		},
		{
			name:   "nil service not served",
			svc:    nil,
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			vip, _, _, ok, _ := serviceToVIP(tc.svc)
			if ok != tc.wantOK {
				t.Fatalf("serviceToVIP ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if vip.Namespace != tc.wantVIP.Namespace || vip.Name != tc.wantVIP.Name || vip.ClusterIP != tc.wantVIP.ClusterIP {
				t.Fatalf("vip identity = %+v, want %+v", vip, tc.wantVIP)
			}
			if len(vip.Ports) != len(tc.wantVIP.Ports) {
				t.Fatalf("vip ports = %+v, want %+v", vip.Ports, tc.wantVIP.Ports)
			}
			for i := range vip.Ports {
				if vip.Ports[i] != tc.wantVIP.Ports[i] {
					t.Fatalf("vip port[%d] = %+v, want %+v", i, vip.Ports[i], tc.wantVIP.Ports[i])
				}
			}
			if err := vip.Validate(); err != nil {
				t.Fatalf("translated VIP fails Validate: %v", err)
			}
		})
	}
}

// TestServiceToVIPInternalTrafficPolicy asserts serviceToVIP reads
// svc.Spec.InternalTrafficPolicy and maps it to the proxy-internal trafficPolicy
// threaded to the routing table: a nil pointer and "Cluster" default to
// trafficCluster, "Local" becomes trafficLocal.
func TestServiceToVIPInternalTrafficPolicy(t *testing.T) {
	t.Parallel()
	local := corev1.ServiceInternalTrafficPolicyLocal
	cluster := corev1.ServiceInternalTrafficPolicyCluster
	mk := func(itp *corev1.ServiceInternalTrafficPolicy) *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"},
			Spec: corev1.ServiceSpec{
				Type:                  corev1.ServiceTypeClusterIP,
				ClusterIP:             "10.43.0.10",
				Ports:                 []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(8080), Protocol: corev1.ProtocolTCP}},
				InternalTrafficPolicy: itp,
			},
		}
	}

	cases := []struct {
		name string
		itp  *corev1.ServiceInternalTrafficPolicy
		want trafficPolicy
	}{
		{"nil defaults to cluster", nil, trafficCluster},
		{"explicit cluster", &cluster, trafficCluster},
		{"local", &local, trafficLocal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, policy, _, ok, _ := serviceToVIP(mk(tc.itp))
			if !ok {
				t.Fatalf("serviceToVIP ok = false, want true")
			}
			if policy != tc.want {
				t.Fatalf("policy = %d, want %d", policy, tc.want)
			}
		})
	}
}

// TestServiceToVIPExternalLocalUnhonored asserts the pure 5th return value: the
// externalLocalUnhonored classification is true iff the Service requests
// externalTrafficPolicy:Local AND serves at least one NodePort — the exact
// configuration k3sm's userspace NodePort splice cannot honor. It reads eTP SOLELY
// for this observability signal; the classification is pure and never logs.
func TestServiceToVIPExternalLocalUnhonored(t *testing.T) {
	t.Parallel()
	mk := func(etp corev1.ServiceExternalTrafficPolicy, nodePort int32) *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"},
			Spec: corev1.ServiceSpec{
				Type:                  corev1.ServiceTypeClusterIP,
				ClusterIP:             "10.43.0.10",
				ExternalTrafficPolicy: etp,
				Ports:                 []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(8080), Protocol: corev1.ProtocolTCP, NodePort: nodePort}},
			},
		}
	}
	cases := []struct {
		name string
		svc  *corev1.Service
		want bool
	}{
		{"local on nodeport is unhonored", mk(corev1.ServiceExternalTrafficPolicyLocal, 30080), true},
		{"local without nodeport is honorable (clusterip-only)", mk(corev1.ServiceExternalTrafficPolicyLocal, 0), false},
		{"cluster on nodeport is honored", mk(corev1.ServiceExternalTrafficPolicyCluster, 30080), false},
		{"unset on nodeport is honored", mk("", 30080), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, _, ok, unhonored := serviceToVIP(tc.svc)
			if !ok {
				t.Fatalf("serviceToVIP ok = false, want true")
			}
			if unhonored != tc.want {
				t.Fatalf("externalLocalUnhonored = %v, want %v", unhonored, tc.want)
			}
		})
	}
}

// TestServiceToVIPSessionAffinity asserts serviceToVIP reads svc.Spec.SessionAffinity
// (+ SessionAffinityConfig.ClientIP.TimeoutSeconds) into the proxy-internal
// affinityConfig, nil-safely: SessionAffinity != ClientIP => no affinity; ClientIP with
// an absent/nil/non-positive timeout => the 3h default (never infinite); ClientIP with a
// positive timeout => that duration.
func TestServiceToVIPSessionAffinity(t *testing.T) {
	t.Parallel()
	mk := func(sa corev1.ServiceAffinity, cfg *corev1.SessionAffinityConfig) *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"},
			Spec: corev1.ServiceSpec{
				Type:                  corev1.ServiceTypeClusterIP,
				ClusterIP:             "10.43.0.10",
				Ports:                 []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(8080), Protocol: corev1.ProtocolTCP}},
				SessionAffinity:       sa,
				SessionAffinityConfig: cfg,
			},
		}
	}
	clientIP := func(secs *int32) *corev1.SessionAffinityConfig {
		return &corev1.SessionAffinityConfig{ClientIP: &corev1.ClientIPConfig{TimeoutSeconds: secs}}
	}

	cases := []struct {
		name        string
		svc         *corev1.Service
		wantMode    affinityMode
		wantTimeout time.Duration
	}{
		{"none is no affinity", mk(corev1.ServiceAffinityNone, nil), affinityNone, 0},
		{"empty is no affinity", mk("", nil), affinityNone, 0},
		{"clientIP nil config defaults to 3h", mk(corev1.ServiceAffinityClientIP, nil), affinityClientIP, affinityDefaultTimeout},
		{"clientIP nil ClientIP defaults to 3h", mk(corev1.ServiceAffinityClientIP, &corev1.SessionAffinityConfig{}), affinityClientIP, affinityDefaultTimeout},
		{"clientIP nil TimeoutSeconds defaults to 3h", mk(corev1.ServiceAffinityClientIP, clientIP(nil)), affinityClientIP, affinityDefaultTimeout},
		{"clientIP explicit timeout", mk(corev1.ServiceAffinityClientIP, clientIP(ptrInt32(3600))), affinityClientIP, time.Hour},
		{"clientIP zero timeout defaults to 3h", mk(corev1.ServiceAffinityClientIP, clientIP(ptrInt32(0))), affinityClientIP, affinityDefaultTimeout},
		{"clientIP negative timeout defaults to 3h", mk(corev1.ServiceAffinityClientIP, clientIP(ptrInt32(-5))), affinityClientIP, affinityDefaultTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, aff, ok, _ := serviceToVIP(tc.svc)
			if !ok {
				t.Fatalf("serviceToVIP ok = false, want true")
			}
			if aff.mode != tc.wantMode {
				t.Fatalf("affinity mode = %d, want %d", aff.mode, tc.wantMode)
			}
			if aff.mode == affinityClientIP && aff.timeout != tc.wantTimeout {
				t.Fatalf("affinity timeout = %v, want %v", aff.timeout, tc.wantTimeout)
			}
		})
	}
}

// TestEndpointsForPort asserts the pure EndpointSlice translator carries Ready
// correctly (nil Ready => not ready) and matches ports by name.
func TestEndpointsForPort(t *testing.T) {
	t.Parallel()

	slice := func(name string, addrType discoveryv1.AddressType, ready []bool, addrs []string, portName *string, port *int32) *discoveryv1.EndpointSlice {
		eps := make([]discoveryv1.Endpoint, len(ready))
		for i := range ready {
			eps[i] = discoveryv1.Endpoint{
				Addresses:  []string{addrs[i]},
				Conditions: discoveryv1.EndpointConditions{Ready: ptrBool(ready[i])},
			}
		}
		return &discoveryv1.EndpointSlice{
			ObjectMeta:  metav1.ObjectMeta{Namespace: "default", Name: name},
			AddressType: addrType,
			Endpoints:   eps,
			Ports:       []discoveryv1.EndpointPort{{Name: portName, Port: port}},
		}
	}

	t.Run("carries ready flag and target port", func(t *testing.T) {
		t.Parallel()
		sl := slice("web-1", discoveryv1.AddressTypeIPv4, []bool{true, false}, []string{"10.42.0.1", "10.42.0.2"}, ptrStr("http"), ptrInt32(8080))
		got := endpointsForPort([]*discoveryv1.EndpointSlice{sl}, "http")
		if len(got) != 2 {
			t.Fatalf("got %d endpoints, want 2", len(got))
		}
		byIP := map[string]netv1.Endpoint{}
		for _, e := range got {
			byIP[e.IP] = e
		}
		if !byIP["10.42.0.1"].Ready || byIP["10.42.0.1"].Port != 8080 {
			t.Fatalf("10.42.0.1 = %+v, want ready port 8080", byIP["10.42.0.1"])
		}
		if byIP["10.42.0.2"].Ready {
			t.Fatalf("10.42.0.2 should be not-ready")
		}
	})

	t.Run("nil ready condition is not ready", func(t *testing.T) {
		t.Parallel()
		sl := &discoveryv1.EndpointSlice{
			ObjectMeta:  metav1.ObjectMeta{Namespace: "default", Name: "web-1"},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.42.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: nil}}},
			Ports:       []discoveryv1.EndpointPort{{Name: ptrStr("http"), Port: ptrInt32(8080)}},
		}
		got := endpointsForPort([]*discoveryv1.EndpointSlice{sl}, "http")
		if len(got) != 1 || got[0].Ready {
			t.Fatalf("nil Ready treated as ready: %+v", got)
		}
	})

	t.Run("port name mismatch contributes nothing", func(t *testing.T) {
		t.Parallel()
		sl := slice("web-1", discoveryv1.AddressTypeIPv4, []bool{true}, []string{"10.42.0.1"}, ptrStr("https"), ptrInt32(8443))
		got := endpointsForPort([]*discoveryv1.EndpointSlice{sl}, "http")
		if len(got) != 0 {
			t.Fatalf("mismatched port name contributed %d endpoints", len(got))
		}
	})

	t.Run("single-port (empty name) matches nil slice port name", func(t *testing.T) {
		t.Parallel()
		sl := slice("web-1", discoveryv1.AddressTypeIPv4, []bool{true}, []string{"10.42.0.1"}, nil, ptrInt32(8080))
		got := endpointsForPort([]*discoveryv1.EndpointSlice{sl}, "")
		if len(got) != 1 || got[0].Port != 8080 {
			t.Fatalf("empty-name match = %+v, want one endpoint on 8080", got)
		}
	})

	t.Run("non-IPv4 address type ignored", func(t *testing.T) {
		t.Parallel()
		sl := slice("web-1", discoveryv1.AddressTypeIPv6, []bool{true}, []string{"fd00::1"}, ptrStr("http"), ptrInt32(8080))
		got := endpointsForPort([]*discoveryv1.EndpointSlice{sl}, "http")
		if len(got) != 0 {
			t.Fatalf("IPv6 slice contributed %d endpoints", len(got))
		}
	})
}
