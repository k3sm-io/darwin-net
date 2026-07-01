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
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	netv1 "k3sm.io/apis/net/v1"
)

// serviceToVIP flattens a Kubernetes Service into the netv1.ServiceVIP the proxy
// owns plus its internal traffic policy and ClientIP session-affinity config, or
// returns (zero, trafficCluster, affinityConfig{}, false) when the Service is not one
// the proxy serves: headless (no/None ClusterIP), ExternalName, or with no ports. The
// trafficPolicy and affinityConfig are read from svc.Spec (InternalTrafficPolicy and
// SessionAffinity) and threaded to the routing table by the reconcile path — neither
// is carried on the netv1 contract (apis), since only the proxy consumes them. It is
// pure (no I/O), so the watch→proxy translation is table-testable independent of
// client-go.
func serviceToVIP(svc *corev1.Service) (netv1.ServiceVIP, trafficPolicy, affinityConfig, bool) {
	if svc == nil {
		return netv1.ServiceVIP{}, trafficCluster, affinityConfig{}, false
	}
	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		return netv1.ServiceVIP{}, trafficCluster, affinityConfig{}, false
	}
	cip := svc.Spec.ClusterIP
	if cip == "" || cip == corev1.ClusterIPNone {
		return netv1.ServiceVIP{}, trafficCluster, affinityConfig{}, false
	}
	if len(svc.Spec.Ports) == 0 {
		return netv1.ServiceVIP{}, trafficCluster, affinityConfig{}, false
	}
	out := netv1.ServiceVIP{
		Namespace: svc.Namespace,
		Name:      svc.Name,
		ClusterIP: cip,
		Ports:     make([]netv1.ServicePort, 0, len(svc.Spec.Ports)),
	}
	for _, p := range svc.Spec.Ports {
		proto := netv1.Protocol(p.Protocol)
		if proto == "" {
			proto = netv1.ProtocolTCP
		}
		// Only TCP/UDP are proxied; SCTP ports are skipped (not modeled).
		if !proto.Valid() {
			continue
		}
		out.Ports = append(out.Ports, netv1.ServicePort{
			Name:       p.Name,
			Port:       p.Port,
			TargetPort: int32(p.TargetPort.IntValue()),
			Protocol:   proto,
			NodePort:   p.NodePort,
		})
	}
	if len(out.Ports) == 0 {
		return netv1.ServiceVIP{}, trafficCluster, affinityConfig{}, false
	}
	return out.WithDefaults(), internalPolicy(svc.Spec.InternalTrafficPolicy), sessionAffinity(&svc.Spec), true
}

// sessionAffinity maps a Service's SessionAffinity spec to the proxy-internal
// affinityConfig: SessionAffinity == ClientIP yields affinityClientIP with the
// configured ClientIP.TimeoutSeconds, and any other value (None/empty) yields the
// zero affinityConfig (no affinity). The nested SessionAffinityConfig / ClientIP /
// TimeoutSeconds are all nil-able even when SessionAffinity == ClientIP, so each hop
// is nil-guarded; an absent or non-positive timeout defaults to affinityDefaultTimeout
// (kube-proxy's 3h DefaultClientIPServiceAffinitySeconds), never an infinite binding.
// Like internalPolicy it is proxy-internal — netv1 carries no SessionAffinity field.
func sessionAffinity(spec *corev1.ServiceSpec) affinityConfig {
	if spec.SessionAffinity != corev1.ServiceAffinityClientIP {
		return affinityConfig{}
	}
	timeout := affinityDefaultTimeout
	if c := spec.SessionAffinityConfig; c != nil && c.ClientIP != nil && c.ClientIP.TimeoutSeconds != nil {
		if secs := *c.ClientIP.TimeoutSeconds; secs > 0 {
			timeout = time.Duration(secs) * time.Second
		}
	}
	return affinityConfig{mode: affinityClientIP, timeout: timeout}
}

// internalPolicy maps a corev1 internalTrafficPolicy pointer to the proxy-internal
// trafficPolicy: a nil pointer or "Cluster" yields trafficCluster (round-robin over
// all backends), "Local" yields trafficLocal (node-local filtering). Any
// unrecognized value defaults to trafficCluster, failing safe to the standard path.
func internalPolicy(p *corev1.ServiceInternalTrafficPolicy) trafficPolicy {
	if p != nil && *p == corev1.ServiceInternalTrafficPolicyLocal {
		return trafficLocal
	}
	return trafficCluster
}

// endpointsForPort extracts the netv1.Endpoints backing the named Service port
// from a set of EndpointSlices. portName is the ServicePort.Name (empty for a
// single-port Service); only slice ports whose name matches contribute, and an
// endpoint's readiness comes from its Conditions.Ready (a nil Ready is treated
// as not ready, matching Kubernetes). It is pure so the readiness/match logic is
// table-testable.
//
// addressType filters which slices count (IPv4 here); FQDN/IPv6 slices are
// ignored for the M1 single-node path.
func endpointsForPort(slices []*discoveryv1.EndpointSlice, portName string) []netv1.Endpoint {
	var out []netv1.Endpoint
	for _, sl := range slices {
		if sl == nil || sl.AddressType != discoveryv1.AddressTypeIPv4 {
			continue
		}
		port, ok := matchSlicePort(sl.Ports, portName)
		if !ok {
			continue
		}
		for _, ep := range sl.Endpoints {
			ready := ep.Conditions.Ready != nil && *ep.Conditions.Ready
			for _, addr := range ep.Addresses {
				out = append(out, netv1.Endpoint{
					IP:    addr,
					Port:  port,
					Ready: ready,
				})
			}
		}
	}
	return out
}

// matchSlicePort returns the resolved backend port for portName within an
// EndpointSlice's ports, and whether it matched. A slice port with a nil Name
// matches the single-port (empty portName) case; a nil Port is skipped.
func matchSlicePort(ports []discoveryv1.EndpointPort, portName string) (int32, bool) {
	for _, p := range ports {
		name := ""
		if p.Name != nil {
			name = *p.Name
		}
		if name != portName {
			continue
		}
		if p.Port == nil {
			return 0, false
		}
		return *p.Port, true
	}
	return 0, false
}
