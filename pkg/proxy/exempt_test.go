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
	"context"
	"net/netip"
	"testing"

	netv1 "k3sm.io/apis/net/v1"
)

// TestKubeDNSVIPExemptFromProxy is the M3.3 acceptance for the kube-dns VIP
// exemption: with WithInfraVIPExemptions(10.43.0.10) the proxy takes NO ownership
// of the kube-dns VIP for either 53/TCP or 53/UDP — no worker, no lo0 alias, no
// routing entry — so per-node CoreDNS (which binds 10.43.0.10:53 directly) never
// hits EADDRINUSE. A normal ClusterIP Service on a different address is still
// claimed, proving the exemption is specific to the kube-dns VIP and not a blanket
// opt-out.
func TestKubeDNSVIPExemptFromProxy(t *testing.T) {
	t.Parallel()

	const kubeDNS = "10.43.0.10"
	kubeDNSAddr := netip.MustParseAddr(kubeDNS)
	const normalVIP = "127.0.0.1"

	alias := newNoopAliasManager()
	tbl := NewRoutingTable(netip.Prefix{})
	p := New(tbl, withAliasManager(alias), WithInfraVIPExemptions(kubeDNSAddr))

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = p.Run(ctx) }()
	defer func() { cancel(); <-runDone }()

	eps := []netv1.Endpoint{{IP: "10.42.0.7", Port: 53, Ready: true}}

	// The kube-dns VIP is reconciled on BOTH protocols — CoreDNS binds each
	// directly, so the proxy must own neither (the M1 UDP path only dodged the
	// collision by accident; TCP had no exemption).
	tcp53 := &netv1.ServicePort{Port: 53, TargetPort: 53, Protocol: netv1.ProtocolTCP}
	udp53 := &netv1.ServicePort{Port: 53, TargetPort: 53, Protocol: netv1.ProtocolUDP}
	if err := p.Reconcile(kubeDNS, tcp53, eps); err != nil {
		t.Fatalf("reconcile kube-dns 53/TCP: %v", err)
	}
	if err := p.Reconcile(kubeDNS, udp53, eps); err != nil {
		t.Fatalf("reconcile kube-dns 53/UDP: %v", err)
	}

	// A normal ClusterIP Service IS still claimed.
	normalPort := freePort(t, normalVIP)
	normalSP := &netv1.ServicePort{Port: normalPort, TargetPort: 8080, Protocol: netv1.ProtocolTCP}
	if err := p.Reconcile(normalVIP, normalSP, eps); err != nil {
		t.Fatalf("reconcile normal vip: %v", err)
	}

	tcpKey := PortKey{ClusterIP: kubeDNS, Port: 53, Protocol: netv1.ProtocolTCP}
	udpKey := PortKey{ClusterIP: kubeDNS, Port: 53, Protocol: netv1.ProtocolUDP}
	normalKey := PortKey{ClusterIP: normalVIP, Port: normalPort, Protocol: netv1.ProtocolTCP}

	// The exemption is synchronous in Reconcile: no worker is ever created for the
	// kube-dns VIP, while the normal VIP gets exactly one.
	p.mu.Lock()
	_, tcpOwned := p.workers[tcpKey]
	_, udpOwned := p.workers[udpKey]
	_, normalOwned := p.workers[normalKey]
	nworkers := len(p.workers)
	p.mu.Unlock()
	if tcpOwned {
		t.Fatalf("proxy created a worker for the exempt kube-dns VIP 53/TCP")
	}
	if udpOwned {
		t.Fatalf("proxy created a worker for the exempt kube-dns VIP 53/UDP")
	}
	if !normalOwned {
		t.Fatalf("proxy did not claim the normal ClusterIP Service (exemption too broad)")
	}
	if nworkers != 1 {
		t.Fatalf("worker count = %d, want 1 (only the normal VIP)", nworkers)
	}

	// The normal VIP's worker brings its listener up; wait so its reconcile
	// (alias ensure + routing) has completed before the assertions below.
	waitListen(t, normalVIP, normalPort)

	// The proxy NEVER aliases the kube-dns VIP — CoreDNS owns the alias + socket.
	if got := alias.ensures(kubeDNSAddr); got != 0 {
		t.Fatalf("proxy ensured the kube-dns lo0 alias %d times, want 0 (CoreDNS owns it)", got)
	}
	// And no routing-table entry exists for either kube-dns key.
	if n := tbl.Len(tcpKey); n != 0 {
		t.Fatalf("routing table has %d backends for exempt kube-dns 53/TCP, want 0", n)
	}
	if n := tbl.Len(udpKey); n != 0 {
		t.Fatalf("routing table has %d backends for exempt kube-dns 53/UDP, want 0", n)
	}
	// The normal VIP IS routed (the proxy still serves non-infra VIPs).
	if n := tbl.Len(normalKey); n != 1 {
		t.Fatalf("routing table has %d backends for the normal VIP, want 1", n)
	}
}
