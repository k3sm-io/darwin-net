//go:build integration

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

// Integration test for the shim's multi-server walk and exclusive mode (the
// dnsPolicy None ABI: K3SM_DNS_SERVERS + K3SM_DNS_EXCLUSIVE). Run with:
//
//	CGO_ENABLED=0 go test -tags integration -run TestGetaddrinfoShimExclusive ./pkg/dns/
package dns

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// hostLineRE matches the shim's host-chokepoint trace line. Because every host
// getaddrinfo consult passes k3sm_host_getaddrinfo (pinned by
// TestShimHostCallsUseChokepoint), the absence of this line under
// K3SM_DNS_DEBUG is proof that no host path was taken.
var hostLineRE = regexp.MustCompile(`(?m)^k3sm-dns: HOST (\S+) node=`)

// probeRun is one probe execution under the shim.
type probeRun struct {
	out     string
	elapsed time.Duration
}

// hostReasons returns the reason of every HOST trace line in the run.
func (p probeRun) hostReasons() []string {
	var out []string
	for _, m := range hostLineRE.FindAllStringSubmatch(p.out, -1) {
		out = append(out, m[1])
	}
	return out
}

// assertNoHost fails when the run consulted the host resolver.
func (p probeRun) assertNoHost(t *testing.T) {
	t.Helper()
	if r := p.hostReasons(); len(r) != 0 {
		t.Fatalf("the host resolver was consulted (HOST %v); want none:\n%s", r, p.out)
	}
}

// assertHost fails unless the run consulted the host resolver with reason.
func (p probeRun) assertHost(t *testing.T, reason string) {
	t.Helper()
	for _, r := range p.hostReasons() {
		if r == reason {
			return
		}
	}
	t.Fatalf("want a HOST %s trace line, got HOST %v:\n%s", reason, p.hostReasons(), p.out)
}

// assertContains fails unless the run's output carries want.
func (p probeRun) assertContains(t *testing.T, want string) {
	t.Helper()
	if !strings.Contains(p.out, want) {
		t.Fatalf("probe output lacks %q:\n%s", want, p.out)
	}
}

// exclusiveHarness holds the built dylib and probe shared by every leg.
type exclusiveHarness struct {
	dylib, probe string
}

// run executes the probe with the shim injected, K3SM_DNS_DEBUG on, and the
// given K3SM_DNS_* env, passing args to the probe.
func (h exclusiveHarness) run(t *testing.T, env []string, args ...string) probeRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.probe, args...)
	cmd.Env = append(append(scrubbedEnv(), env...),
		EnvDNSDebug+"=1",
		"DYLD_INSERT_LIBRARIES="+h.dylib,
	)
	start := time.Now()
	out, _ := cmd.CombinedOutput()
	run := probeRun{out: string(out), elapsed: time.Since(start)}
	if !strings.Contains(run.out, "k3sm-dns: getaddrinfo node=") {
		t.Fatalf("the shim did not trace this call — the dylib did not load:\n%s", run.out)
	}
	return run
}

// scrubbedEnv is the test process environment minus any K3SM_DNS_* key, so an
// ambient value can never leak into a leg's configuration.
func scrubbedEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "K3SM_DNS_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// serverToken renders a stub's "127.0.0.1:port" K3SM_DNS_SERVERS token.
func serverToken(port int) string { return "127.0.0.1:" + strconv.Itoa(port) }

// serversEnv renders a K3SM_DNS_SERVERS assignment from stub ports.
func serversEnv(ports ...int) string {
	toks := make([]string, len(ports))
	for i, p := range ports {
		toks[i] = serverToken(p)
	}
	return EnvDNSServers + "=" + strings.Join(toks, " ")
}

// TestGetaddrinfoShimExclusive pins the multi-server walk and exclusive mode of
// the real dylib, one subtest per leg. Every leg runs with K3SM_DNS_DEBUG, so a
// "no HOST line" assertion observes every host path; leg (b)'s paired control
// proves that oracle is live.
func TestGetaddrinfoShimExclusive(t *testing.T) {
	// A missing toolchain is an environment defect, not a result: a skipped gate
	// reads like a passing one.
	if _, err := exec.LookPath("clang"); err != nil {
		t.Fatalf("clang is required for the shim exclusive-mode gate (this gate must not be skipped): %v", err)
	}
	h := exclusiveHarness{dylib: buildShim(t), probe: buildProbe(t)}
	want := netip.MustParseAddr("10.9.9.9")
	other := netip.MustParseAddr("10.8.8.8")
	excl := EnvDNSExclusive + "=1"

	t.Run("a: server 1 dead, server 2 answers, dead server asked once per call", func(t *testing.T) {
		dead := newStubDNS(t, map[string]netip.Addr{})
		defer dead.close()
		dead.setSilent()
		live := newStubDNS(t, map[string]netip.Addr{"web.b.example": want})
		defer live.close()

		run := h.run(t, []string{serversEnv(dead.port(), live.port()), excl,
			EnvDNSSearch + "=a.example b.example", EnvDNSNdots + "=5"}, "web")
		run.assertContains(t, want.String())
		run.assertNoHost(t)
		// Two candidates were walked (web.a.example missed on server 2, then
		// web.b.example hit), yet the dead server saw exactly one query: the
		// dead-server memo, not a per-candidate retry.
		if n := dead.queryCount(); n != 1 {
			t.Fatalf("dead server asked %d times, want 1 (dead for the rest of the call):\n%s", n, run.out)
		}
		if !live.asked("web.a.example") {
			t.Fatalf("server 2 never saw the first candidate:\n%s", run.out)
		}
	})

	t.Run("b: exclusive, every server misses, EAI_NONAME and no HOST; paired non-exclusive control does consult HOST", func(t *testing.T) {
		s1 := newStubDNS(t, map[string]netip.Addr{})
		defer s1.close()
		s2 := newStubDNS(t, map[string]netip.Addr{})
		defer s2.close()
		env := []string{serversEnv(s1.port(), s2.port()), EnvDNSNdots + "=5"}

		run := h.run(t, append(env, excl), "nothere.invalid.")
		run.assertContains(t, "EAI_NONAME")
		run.assertNoHost(t)

		control := h.run(t, env, "nothere.invalid.")
		control.assertHost(t, "all-missed")
	})

	t.Run("c: exclusive external transient is EAI_AGAIN with no HOST", func(t *testing.T) {
		s1 := newStubDNS(t, map[string]netip.Addr{})
		defer s1.close()
		s1.setServfail("ext.example.invalid")
		s2 := newStubDNS(t, map[string]netip.Addr{})
		defer s2.close()
		s2.setServfail("ext.example.invalid")

		run := h.run(t, []string{serversEnv(s1.port(), s2.port()), excl, EnvDNSNdots + "=5"}, "ext.example.invalid.")
		run.assertContains(t, "EAI_AGAIN")
		run.assertNoHost(t)
		if !s1.asked("ext.example.invalid") || !s2.asked("ext.example.invalid") {
			t.Fatalf("both servers must be asked before failing closed:\n%s", run.out)
		}
	})

	t.Run("d: exclusive named service resolves the name via the pod's servers and the port locally", func(t *testing.T) {
		s := newStubDNS(t, map[string]netip.Addr{"svc.example": want})
		defer s.close()

		run := h.run(t, []string{serversEnv(s.port()), excl, EnvDNSNdots + "=5"}, "svc.example", "https")
		run.assertContains(t, want.String()+":443")
		run.assertNoHost(t)
		if !s.asked("svc.example") {
			t.Fatalf("the name was not resolved through the pod's server:\n%s", run.out)
		}
	})

	t.Run("e: exclusive AF_INET6 hints for a name is EAI_NONAME with no HOST and no query", func(t *testing.T) {
		s := newStubDNS(t, map[string]netip.Addr{"web": want})
		defer s.close()

		run := h.run(t, []string{serversEnv(s.port()), excl}, "web", "-", "inet6")
		run.assertContains(t, "EAI_NONAME")
		run.assertNoHost(t)
		if n := s.queryCount(); n != 0 {
			t.Fatalf("an AF_INET6 request queried the pod's server %d times; the shim serves no AAAA", n)
		}
	})

	t.Run("f: exclusive localhost is the documented host residual", func(t *testing.T) {
		s := newStubDNS(t, map[string]netip.Addr{})
		defer s.close()

		run := h.run(t, []string{serversEnv(s.port()), excl}, "localhost")
		run.assertContains(t, "127.0.0.1")
		run.assertHost(t, "localhost")
		if n := s.queryCount(); n != 0 {
			t.Fatalf("localhost reached the pod's server (%d queries)", n)
		}
	})

	t.Run("g: three silent servers cost one timeout each, then EAI_AGAIN", func(t *testing.T) {
		run := h.run(t, []string{
			serversEnv(newBlackholeDNS(t), newBlackholeDNS(t), newBlackholeDNS(t)), excl,
			EnvDNSSearch + "=a.example b.example c.example", EnvDNSNdots + "=5",
		}, "web")
		run.assertContains(t, "EAI_AGAIN")
		run.assertNoHost(t)
		// 3 servers x K3SM_DNS_TIMEOUT_SEC (2s), once each per call however many
		// candidates "web" expands to. Without the memo the walk would retry.
		if run.elapsed < 5500*time.Millisecond || run.elapsed > 7*time.Second {
			t.Fatalf("elapsed %v, want within [5.5s, 7s] (3 servers x 2s timeout, each once per call):\n%s", run.elapsed, run.out)
		}
	})

	t.Run("h: old env with only K3SM_DNS_SERVER behaves as before", func(t *testing.T) {
		s := newStubDNS(t, map[string]netip.Addr{"web.default.svc.cluster.local": want})
		defer s.close()
		env := []string{
			EnvDNSServer + "=127.0.0.1",
			EnvDNSPort + "=" + strconv.Itoa(s.port()),
			EnvDNSDomain + "=cluster.local",
			EnvDNSSearch + "=default.svc.cluster.local svc.cluster.local cluster.local",
			EnvDNSNdots + "=5",
		}
		run := h.run(t, env, "web")
		run.assertContains(t, want.String())
		run.assertNoHost(t)
		// A name the cluster resolver misses still falls through, as today.
		miss := h.run(t, env, "nothere.invalid.")
		miss.assertHost(t, "all-missed")
	})

	t.Run("i: exclusive with no usable server fails every name lookup closed", func(t *testing.T) {
		for _, servers := range []string{
			EnvDNSServers + "=garbage 999.1.1.1 1.2.3.4:0 1.2.3.4:99999 ::1 " + strings.Repeat("1", 70),
			EnvDNSServers + "=",
		} {
			run := h.run(t, []string{servers, excl}, "web")
			run.assertContains(t, "EAI_AGAIN")
			run.assertNoHost(t)
		}
	})

	t.Run("j: only the first three K3SM_DNS_SERVERS tokens are used", func(t *testing.T) {
		// The first three SERVFAIL, which advances the walk to the next server, so
		// the walk visits every kept server; a fourth server, if kept, would HIT.
		var stubs []*stubDNS
		for range 3 {
			s := newStubDNS(t, map[string]netip.Addr{})
			defer s.close()
			s.setServfail("web.invalid")
			stubs = append(stubs, s)
		}
		fourth := newStubDNS(t, map[string]netip.Addr{"web.invalid": want})
		defer fourth.close()

		run := h.run(t, []string{serversEnv(stubs[0].port(), stubs[1].port(), stubs[2].port(), fourth.port()), excl}, "web.invalid.")
		run.assertContains(t, "EAI_AGAIN")
		run.assertNoHost(t)
		for i, s := range stubs {
			if !s.asked("web.invalid") {
				t.Fatalf("server %d of the first three was not asked:\n%s", i+1, run.out)
			}
		}
		if n := fourth.queryCount(); n != 0 {
			t.Fatalf("the fourth token was used (%d queries); at most K3SM_MAX_NS servers are kept", n)
		}
	})

	t.Run("k: K3SM_DNS_SERVERS wins over K3SM_DNS_SERVER", func(t *testing.T) {
		single := newStubDNS(t, map[string]netip.Addr{"web.invalid": other})
		defer single.close()
		list := newStubDNS(t, map[string]netip.Addr{"web.invalid": want})
		defer list.close()

		run := h.run(t, []string{
			EnvDNSServer + "=127.0.0.1",
			EnvDNSPort + "=" + strconv.Itoa(single.port()),
			serversEnv(list.port()),
		}, "web.invalid.")
		run.assertContains(t, want.String())
		if n := single.queryCount(); n != 0 {
			t.Fatalf("K3SM_DNS_SERVER was queried (%d) although K3SM_DNS_SERVERS was set", n)
		}
	})

	for _, family := range []string{"unspec", "inet6"} {
		t.Run("IPv6 literal under "+family+" is the numeric host residual", func(t *testing.T) {
			s := newStubDNS(t, map[string]netip.Addr{})
			defer s.close()

			run := h.run(t, []string{serversEnv(s.port()), excl}, "::1", "-", family)
			run.assertContains(t, "::1")
			run.assertHost(t, "numeric6")
			if n := s.queryCount(); n != 0 {
				t.Fatalf("an IPv6 literal reached the pod's server (%d queries)", n)
			}
		})
	}

	for _, name := range []string{"a.localhost", "LOCALHOST.", "Sub.LocalHost"} {
		t.Run("localhost match "+name+" is the host residual", func(t *testing.T) {
			s := newStubDNS(t, map[string]netip.Addr{})
			defer s.close()

			run := h.run(t, []string{serversEnv(s.port()), excl}, name)
			run.assertHost(t, "localhost")
			if n := s.queryCount(); n != 0 {
				t.Fatalf("%s reached the pod's server (%d queries)", name, n)
			}
		})
	}

	for _, name := range []string{"notlocalhost", "localhost.example"} {
		t.Run("localhost non-match "+name+" goes to the pod's servers", func(t *testing.T) {
			s := newStubDNS(t, map[string]netip.Addr{})
			defer s.close()

			run := h.run(t, []string{serversEnv(s.port()), excl, EnvDNSNdots + "=5"}, name)
			run.assertContains(t, "EAI_NONAME")
			run.assertNoHost(t)
			if !s.asked(name) {
				t.Fatalf("%s did not reach the pod's server:\n%s", name, run.out)
			}
		})
	}

	t.Run("unknown named service is EAI_SERVICE with no HOST and no query", func(t *testing.T) {
		s := newStubDNS(t, map[string]netip.Addr{"web": want})
		defer s.close()

		run := h.run(t, []string{serversEnv(s.port()), excl}, "web", "k3sm-no-such-service")
		run.assertContains(t, "EAI_SERVICE")
		run.assertNoHost(t)
		if n := s.queryCount(); n != 0 {
			t.Fatalf("an unknown service still queried the pod's server (%d queries)", n)
		}
	})
}
