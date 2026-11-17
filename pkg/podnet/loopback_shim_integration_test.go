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

package podnet

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The loopback gate's pod address: a lo0 /32 alias in RFC 5737 TEST-NET-3, so it
// can never be a real pod address the node IPAM hands out (100.64.0.0/10).
const (
	lbTestPodIP    = "203.0.113.151"
	lbTestCluster  = "203.0.113.0/24"
	lbTestBasePort = 18640 // the harness listens on 18640..18643
)

// TestShimLoopbackConnectReachesOwnPodListener is the B1845 gate. One harness
// process plays a pod with the REAL shim injected (built by hack/build-shim.sh)
// and K3SM_POD_IP set: its wildcard listeners are moved onto the pod address by
// the bind rung, and its loopback dials must reach them. Beside it the test runs
// listeners of its own on 127.0.0.1, standing for the host's loopback services,
// which must answer exactly as they did before: reachable when the pod holds no
// socket on the port, and losing to the pod's own listener when it does.
//
// It needs root for the lo0 alias only. Run it with:
//
//	CGO_ENABLED=0 go test -c -tags integration -o podnet.test ./pkg/podnet/
//	sudo ./podnet.test -test.run TestShimLoopbackConnectReachesOwnPodListener -test.v
func TestShimLoopbackConnectReachesOwnPodListener(t *testing.T) {
	requireRoot(t)
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skipf("clang not on PATH, cannot build the shim or the harness: %v", err)
	}
	root := icRepoRoot(t)
	work := t.TempDir()
	if out, err := exec.Command("bash", filepath.Join(root, "hack", "build-shim.sh"), work).CombinedOutput(); err != nil {
		t.Fatalf("build-shim.sh: %v\n%s", err, out)
	}
	dylib := filepath.Join(work, "libk3sm_getaddrinfo_shim.dylib")
	harness := filepath.Join(work, "loopbackcases")
	if out, err := exec.Command("clang", "-O2", "-Wall", "-Wextra", "-o", harness,
		filepath.Join(root, "pkg", "podnet", "testdata", "loopbackcases.c")).CombinedOutput(); err != nil {
		t.Fatalf("compile loopbackcases.c: %v\n%s", err, out)
	}

	ctx := context.Background()
	alias := netip.MustParseAddr(lbTestPodIP)
	if lo0HasAddr(t, alias) {
		t.Fatalf("precondition: %s is already on lo0; refusing to touch an address this test did not add", alias)
	}
	mgr := newLo0AliasManager(netip.Prefix{})
	if err := mgr.Ensure(ctx, alias); err != nil {
		t.Fatalf("add lo0 alias %s: %v", alias, err)
	}
	t.Cleanup(func() { _ = mgr.Remove(ctx, alias) })

	// The host's loopback services: each answers a connection with the byte 'H'.
	hostListen := func() int {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("host listener: %v", err)
		}
		t.Cleanup(func() { _ = l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_, _ = c.Write([]byte("H"))
				_ = c.Close()
			}
		}()
		return l.Addr().(*net.TCPAddr).Port
	}
	hostPort := hostListen()
	sharedPort := hostListen()
	absent, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick an absent port: %v", err)
	}
	absentPort := absent.Addr().(*net.TCPAddr).Port
	_ = absent.Close()

	cmd := exec.Command(harness, strconv.Itoa(lbTestBasePort), strconv.Itoa(hostPort),
		strconv.Itoa(sharedPort), strconv.Itoa(absentPort))
	cmd.Env = []string{"PATH=/usr/bin:/bin", "DYLD_INSERT_LIBRARIES=" + dylib, "K3SM_BIND_DEBUG=1",
		"K3SM_POD_IP=" + lbTestPodIP, "K3SM_CLUSTER_CIDRS=" + lbTestCluster}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("harness: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	cases := map[string]map[string]string{}
	for _, line := range strings.Split(stdout.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], "CASE=") {
			continue
		}
		kv := map[string]string{}
		for _, f := range fields[1:] {
			if k, v, ok := strings.Cut(f, "="); ok {
				kv[k] = v
			}
		}
		cases[strings.TrimPrefix(fields[0], "CASE=")] = kv
	}
	trace := stderr.String()
	t.Logf("harness:\n%s", stdout.String())

	// The bind rung must have moved the harness's wildcard listeners, or the
	// loopback dials below would reach them through the host's own 127.0.0.1
	// and prove nothing.
	if want := "-> REWRITE " + lbTestPodIP + ":" + strconv.Itoa(lbTestBasePort); !strings.Contains(trace, want) {
		t.Fatalf("precondition: the bind rung did not move the pod's listener (%q missing):\n%s", want, trace)
	}

	for _, tc := range []struct {
		name, got, traceWant string
	}{
		{"own_tcp", "pod", "dst 127.0.0.1:" + strconv.Itoa(lbTestBasePort) + " -> LOOPBACK-OWN " + lbTestPodIP},
		{"own_tcp_other_loopback", "pod", "dst 127.0.0.2:" + strconv.Itoa(lbTestBasePort) + " -> LOOPBACK-OWN"},
		{"own_dualstack_via_v4", "pod", "dst 127.0.0.1:" + strconv.Itoa(lbTestBasePort+1) + " -> LOOPBACK-OWN"},
		{"own_dualstack_via_v6", "pod", "[loopback6]:" + strconv.Itoa(lbTestBasePort+1) + " -> LOOPBACK-OWN [::ffff:" + lbTestPodIP + "]"},
		{"own_udp_connected", "pod", "connect fd="},
		{"own_udp_sendto", "pod", "sendto fd="},
		{"own_explicit_loopback", "pod", "dst 127.0.0.1:" + strconv.Itoa(lbTestBasePort+3) + " -> LOOPBACK-PASSTHROUGH"},
		{"host_loopback", "host", "dst 127.0.0.1:" + strconv.Itoa(hostPort) + " -> LOOPBACK-PASSTHROUGH"},
		{"shared_port_pod_wins", "pod", "dst 127.0.0.1:" + strconv.Itoa(sharedPort) + " -> LOOPBACK-OWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := cases[tc.name]
			if !ok {
				t.Fatalf("harness printed no %s case", tc.name)
			}
			if c["RC"] != "0" || c["GOT"] != tc.got {
				t.Errorf("%s: RC=%s ERRNO=%s GOT=%s, want RC=0 GOT=%s", tc.name, c["RC"], c["ERRNO"], c["GOT"], tc.got)
			}
			if !strings.Contains(trace, tc.traceWant) {
				t.Errorf("trace lacks %q:\n%s", tc.traceWant, trace)
			}
		})
	}
	t.Run("absent port stays refused", func(t *testing.T) {
		c := cases["absent"]
		if c["RC"] == "0" {
			t.Errorf("a dial to a port nothing holds connected: %v", c)
		}
		if want := "dst 127.0.0.1:" + strconv.Itoa(absentPort) + " -> LOOPBACK-PASSTHROUGH"; !strings.Contains(trace, want) {
			t.Errorf("trace lacks %q:\n%s", want, trace)
		}
	})
}
