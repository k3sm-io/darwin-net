package proxy

import (
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	netv1 "k3sm.io/apis/net/v1"
)

// serviceToVIP flattens a Kubernetes Service into the netv1.ServiceVIP the proxy
// owns, or returns (zero, false) when the Service is not one the proxy serves:
// headless (no/None ClusterIP), ExternalName, or with no ports. It is pure (no
// I/O), so the watch→proxy translation is table-testable independent of client-go.
func serviceToVIP(svc *corev1.Service) (netv1.ServiceVIP, bool) {
	if svc == nil {
		return netv1.ServiceVIP{}, false
	}
	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		return netv1.ServiceVIP{}, false
	}
	cip := svc.Spec.ClusterIP
	if cip == "" || cip == corev1.ClusterIPNone {
		return netv1.ServiceVIP{}, false
	}
	if len(svc.Spec.Ports) == 0 {
		return netv1.ServiceVIP{}, false
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
		return netv1.ServiceVIP{}, false
	}
	return out.WithDefaults(), true
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
