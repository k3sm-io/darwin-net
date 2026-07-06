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
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

// TestHeadlessAndSRVRecordSynthesis is the M10.1 / B81 gate: the pure
// record-synthesis library produces headless A / StatefulSet-identity A / SRV /
// PTR sets per upstream kube-dns semantics, filters readiness, honors
// publishNotReadyAddresses, and the dashed-IP pod decoder round-trips and
// rejects malformed shapes — all watch-free, over consumer-side input structs.
func TestHeadlessAndSRVRecordSynthesis(t *testing.T) {
	const domain = "cluster.local"
	mustAddr := netip.MustParseAddr

	// web: a headless StatefulSet-backed service, two ready hostname-carrying
	// pods, one ready hostname-less pod, one NOT-ready pod.
	web := SynthService{
		Name:      "web",
		Namespace: "prod",
		Headless:  true,
		Ports: []SynthPort{
			{Name: "http", Port: 8080, Protocol: "TCP"},
			{Port: 9090}, // unnamed: must synthesize no SRV
		},
	}
	webEndpoints := []SynthEndpoint{
		{IP: mustAddr("100.64.0.10"), Hostname: "web-0", Ready: true},
		{IP: mustAddr("100.64.0.11"), Hostname: "web-1", Ready: true},
		{IP: mustAddr("100.64.0.12"), Ready: true},                     // no hostname: dashed-IP name
		{IP: mustAddr("100.64.0.13"), Hostname: "web-3", Ready: false}, // rolling out: must be filtered
	}

	t.Run("headless all-ready A set filters not-ready", func(t *testing.T) {
		rs, err := Synthesize(domain, web, webEndpoints)
		if err != nil {
			t.Fatalf("Synthesize: %v", err)
		}
		want := []netip.Addr{mustAddr("100.64.0.10"), mustAddr("100.64.0.11"), mustAddr("100.64.0.12")}
		if got := rs.A["web.prod.svc.cluster.local"]; !reflect.DeepEqual(got, want) {
			t.Fatalf("headless A set = %v, want %v (ready backends only)", got, want)
		}
		// The not-ready endpoint must be absent EVERYWHERE: A, identity, SRV, PTR.
		for name, addrs := range rs.A {
			for _, a := range addrs {
				if a == mustAddr("100.64.0.13") {
					t.Fatalf("not-ready endpoint 100.64.0.13 leaked into A[%s]", name)
				}
			}
		}
		if _, ok := rs.A["web-3.web.prod.svc.cluster.local"]; ok {
			t.Fatal("not-ready endpoint web-3 got an identity A record")
		}
		for _, srv := range rs.SRV["_http._tcp.web.prod.svc.cluster.local"] {
			if srv.Target == "web-3.web.prod.svc.cluster.local" {
				t.Fatal("not-ready endpoint web-3 leaked into the SRV set")
			}
		}
		rev, err := ReverseName(mustAddr("100.64.0.13"))
		if err != nil {
			t.Fatalf("ReverseName: %v", err)
		}
		if owner, ok := rs.PTR[rev]; ok {
			t.Fatalf("not-ready endpoint got a PTR record -> %s", owner)
		}
	})

	t.Run("publishNotReadyAddresses includes the not-ready endpoint", func(t *testing.T) {
		published := web
		published.PublishNotReadyAddresses = true
		rs, err := Synthesize(domain, published, webEndpoints)
		if err != nil {
			t.Fatalf("Synthesize: %v", err)
		}
		want := []netip.Addr{
			mustAddr("100.64.0.10"), mustAddr("100.64.0.11"),
			mustAddr("100.64.0.12"), mustAddr("100.64.0.13"),
		}
		if got := rs.A["web.prod.svc.cluster.local"]; !reflect.DeepEqual(got, want) {
			t.Fatalf("published A set = %v, want all four backends %v", got, want)
		}
		if got, ok := rs.A["web-3.web.prod.svc.cluster.local"]; !ok || got[0] != mustAddr("100.64.0.13") {
			t.Fatalf("published identity A for web-3 = %v,%v, want [100.64.0.13],true", got, ok)
		}
	})

	t.Run("hostname identity A records exactly for hostname-carrying endpoints", func(t *testing.T) {
		rs, err := Synthesize(domain, web, webEndpoints)
		if err != nil {
			t.Fatalf("Synthesize: %v", err)
		}
		wantIdentity := map[string]netip.Addr{
			"web-0.web.prod.svc.cluster.local": mustAddr("100.64.0.10"),
			"web-1.web.prod.svc.cluster.local": mustAddr("100.64.0.11"),
		}
		for name, ip := range wantIdentity {
			got, ok := rs.A[name]
			if !ok || len(got) != 1 || got[0] != ip {
				t.Fatalf("identity A[%s] = %v,%v, want [%s],true", name, got, ok, ip)
			}
		}
		// The hostname-less endpoint gets a dashed-IP name, never a hostname one,
		// so its SRV target still resolves.
		if got, ok := rs.A["100-64-0-12.web.prod.svc.cluster.local"]; !ok || got[0] != mustAddr("100.64.0.12") {
			t.Fatalf("dashed-IP A for hostname-less endpoint = %v,%v, want [100.64.0.12],true", got, ok)
		}
		// Exactly: the service name + one owner name per included endpoint.
		if got, want := len(rs.A), 1+3; got != want {
			t.Fatalf("A owner-name count = %d, want %d (service + 3 included endpoints): %v", got, want, rs.A)
		}
	})

	t.Run("SRV headless per-endpoint targets", func(t *testing.T) {
		rs, err := Synthesize(domain, web, webEndpoints)
		if err != nil {
			t.Fatalf("Synthesize: %v", err)
		}
		srv := rs.SRV["_http._tcp.web.prod.svc.cluster.local"]
		want := []SRVRecord{
			{Target: "100-64-0-12.web.prod.svc.cluster.local", Port: 8080, Priority: 0, Weight: 33},
			{Target: "web-0.web.prod.svc.cluster.local", Port: 8080, Priority: 0, Weight: 33},
			{Target: "web-1.web.prod.svc.cluster.local", Port: 8080, Priority: 0, Weight: 33},
		}
		if !reflect.DeepEqual(srv, want) {
			t.Fatalf("headless SRV = %v, want per-endpoint targets %v", srv, want)
		}
		// Every SRV target must resolve via the same RecordSet.
		for _, r := range srv {
			if _, ok := rs.A[r.Target]; !ok {
				t.Fatalf("SRV target %s has no A record in the set", r.Target)
			}
		}
		if got := len(rs.SRV); got != 1 {
			t.Fatalf("SRV owner-name count = %d, want 1 (the unnamed port synthesizes none): %v", got, rs.SRV)
		}
	})

	t.Run("SRV normal service targets the single VIP name", func(t *testing.T) {
		api := SynthService{
			Name:      "api",
			Namespace: "prod",
			ClusterIP: mustAddr("10.43.0.20"),
			Ports:     []SynthPort{{Name: "grpc", Port: 443, Protocol: "tcp"}},
		}
		// Endpoints are ignored for a normal service: DNS answers the VIP only.
		rs, err := Synthesize(domain, api, webEndpoints)
		if err != nil {
			t.Fatalf("Synthesize: %v", err)
		}
		if got, want := rs.A["api.prod.svc.cluster.local"], []netip.Addr{mustAddr("10.43.0.20")}; !reflect.DeepEqual(got, want) {
			t.Fatalf("normal A = %v, want %v", got, want)
		}
		wantSRV := []SRVRecord{{Target: "api.prod.svc.cluster.local", Port: 443, Priority: 0, Weight: 100}}
		if got := rs.SRV["_grpc._tcp.api.prod.svc.cluster.local"]; !reflect.DeepEqual(got, wantSRV) {
			t.Fatalf("normal SRV = %v, want single VIP-name target %v", got, wantSRV)
		}
		if got := len(rs.A); got != 1 {
			t.Fatalf("normal service A count = %d, want 1 (no per-endpoint records): %v", got, rs.A)
		}
	})

	t.Run("PTR for ClusterIPs and pod IPs", func(t *testing.T) {
		api := SynthService{Name: "api", Namespace: "prod", ClusterIP: mustAddr("10.43.0.20")}
		vipSet, err := Synthesize(domain, api, nil)
		if err != nil {
			t.Fatalf("Synthesize(api): %v", err)
		}
		if got := vipSet.PTR["20.0.43.10.in-addr.arpa"]; got != "api.prod.svc.cluster.local" {
			t.Fatalf("VIP PTR = %q, want the service name", got)
		}
		podSet, err := Synthesize(domain, web, webEndpoints)
		if err != nil {
			t.Fatalf("Synthesize(web): %v", err)
		}
		wantPTR := map[string]string{
			"10.0.64.100.in-addr.arpa": "web-0.web.prod.svc.cluster.local",       // hostname-qualified
			"11.0.64.100.in-addr.arpa": "web-1.web.prod.svc.cluster.local",       // hostname-qualified
			"12.0.64.100.in-addr.arpa": "100-64-0-12.web.prod.svc.cluster.local", // dashed-IP pod name
		}
		if !reflect.DeepEqual(podSet.PTR, wantPTR) {
			t.Fatalf("pod PTR set = %v, want %v", podSet.PTR, wantPTR)
		}
	})

	t.Run("dashed-IP pod decoder round-trip", func(t *testing.T) {
		for _, tc := range []struct {
			ip, ns string
		}{
			{"100.64.0.7", "default"},
			{"100.64.3.254", "prod"},
			{"10.0.0.1", "kube-system"},
		} {
			name, err := PodDNSName(netip.MustParseAddr(tc.ip), tc.ns, domain)
			if err != nil {
				t.Fatalf("PodDNSName(%s, %s): %v", tc.ip, tc.ns, err)
			}
			ip, ns, err := PodAddrFromName(name, domain)
			if err != nil {
				t.Fatalf("PodAddrFromName(%s): %v", name, err)
			}
			if ip != netip.MustParseAddr(tc.ip) || ns != tc.ns {
				t.Fatalf("round-trip %s/%s -> %s -> %s/%s", tc.ip, tc.ns, name, ip, ns)
			}
		}
		// Trailing dot and mixed case are accepted (DNS is case-insensitive).
		ip, ns, err := PodAddrFromName("100-64-0-7.Default.POD.Cluster.Local.", domain)
		if err != nil || ip != netip.MustParseAddr("100.64.0.7") || ns != "default" {
			t.Fatalf("case/dot-tolerant decode = %s,%s,%v, want 100.64.0.7,default,nil", ip, ns, err)
		}
	})

	t.Run("dashed-IP pod decoder rejects bad shapes", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			query string
		}{
			{"wrong suffix (svc not pod)", "100-64-0-7.default.svc.cluster.local"},
			{"wrong domain", "100-64-0-7.default.pod.other.domain"},
			{"missing namespace", "100-64-0-7.pod.cluster.local"},
			{"extra label", "x.100-64-0-7.default.pod.cluster.local"},
			{"too few octets", "100-64-0.default.pod.cluster.local"},
			{"too many octets", "100-64-0-7-9.default.pod.cluster.local"},
			{"octet out of range", "100-64-0-256.default.pod.cluster.local"},
			{"leading zero octet", "100-064-0-7.default.pod.cluster.local"},
			{"empty octet", "100--0-7.default.pod.cluster.local"},
			{"not numeric", "a-b-c-d.default.pod.cluster.local"},
			{"bare domain", "pod.cluster.local"},
			{"empty", ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if _, _, err := PodAddrFromName(tc.query, domain); !errors.Is(err, ErrNotPodName) {
					t.Fatalf("PodAddrFromName(%q) err = %v, want ErrNotPodName", tc.query, err)
				}
			})
		}
	})
}

// TestSynthesizeInputValidation proves malformed synthesis inputs fail fast
// with ErrSynthInput instead of emitting broken record sets.
func TestSynthesizeInputValidation(t *testing.T) {
	mustAddr := netip.MustParseAddr
	valid := SynthService{Name: "web", Namespace: "prod", Headless: true}
	for _, tc := range []struct {
		name      string
		domain    string
		svc       SynthService
		endpoints []SynthEndpoint
	}{
		{"empty domain", "", valid, nil},
		{"bad domain label", "cluster..local", valid, nil},
		{"empty service name", "cluster.local", SynthService{Namespace: "prod"}, nil},
		{"bad namespace", "cluster.local", SynthService{Name: "web", Namespace: "Prod Team"}, nil},
		{"normal service without ClusterIP", "cluster.local", SynthService{Name: "web", Namespace: "prod"}, nil},
		{"bad endpoint hostname", "cluster.local", valid,
			[]SynthEndpoint{{IP: mustAddr("100.64.0.10"), Hostname: "web_0", Ready: true}}},
		{"invalid endpoint address", "cluster.local", valid,
			[]SynthEndpoint{{IP: netip.Addr{}, Ready: true}}},
		{"bad port name", "cluster.local",
			SynthService{Name: "web", Namespace: "prod", Headless: true,
				Ports: []SynthPort{{Name: "http port", Port: 80}}},
			[]SynthEndpoint{{IP: mustAddr("100.64.0.10"), Ready: true}}},
		{"bad protocol", "cluster.local",
			SynthService{Name: "web", Namespace: "prod", Headless: true,
				Ports: []SynthPort{{Name: "http", Port: 80, Protocol: "icmp"}}},
			[]SynthEndpoint{{IP: mustAddr("100.64.0.10"), Ready: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Synthesize(tc.domain, tc.svc, tc.endpoints); !errors.Is(err, ErrSynthInput) {
				t.Fatalf("Synthesize err = %v, want ErrSynthInput", err)
			}
		})
	}
}
