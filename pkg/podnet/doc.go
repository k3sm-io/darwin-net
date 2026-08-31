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

// Package podnet is k3sm's IP-per-pod CNI seam: the macOS-native analog of a CNI
// plugin's ADD/DEL, giving each Pod (a native Darwin process, no network
// namespace) its own IP. The IP is a /32 alias on lo0 carved from the node's
// podCIDR; a DYLD-injected bind() interpose (shim/getaddrinfo_shim.c) then
// rewrites the pod's own wildcard binds onto that /32, using this package's
// env ABI (env.go) to learn which address, so same-node pod-to-pod traffic
// stays on loopback with the source IP preserved by XNU and the address is
// the routable identity reachable over the wireguard mesh in M3.
//
// # Layers
//
//   - Allocator (allocator.go) is the pure-logic IPAM core: it carves the node's
//     per-node /24 out of the cluster podCIDR (100.64.0.0/10) deterministically
//     from the node index, then hands out unique host /32s from that /24 and
//     tracks them so release is leak-free and double-allocation is impossible. It
//     owns no interface and performs no syscalls, so its allocate/release behavior
//     is fully table-tested without privilege, and the per-node carve is stable
//     across a restart (same node index => same /24).
//   - aliasManager (alias.go) abstracts lo0 alias create/teardown, mirroring the
//     Service proxy's seam. The production lo0AliasManager shells out to
//     `ifconfig lo0 alias <ip>/32` (root-gated, run inside the netd daemon
//     boundary in deployment). Tests use the rootless fakeAliasManager; the
//     root-gated integration test drives the real one against a live lo0.
//   - Network (podnet.go) implements PodNetwork, the seam the runtime calls during
//     pod setup/teardown: Setup allocates an IP, plumbs the lo0 alias, and returns
//     the bindable address; Teardown removes the alias and releases the IP. Setup
//     is idempotent per pod (a repeated Setup returns the same IP) and Teardown is
//     leak-free (tearing an unknown pod down is a no-op success), so a crash-
//     recovery reconcile cannot leak addresses.
//
// # Bind discipline (shipped B216 — darwin-net#62)
//
// podnet only provisions the address (the returned IP flows into runtime/v1
// PodBox.pod_ip); the bind rewrite itself happens IN the pod process, via a
// DYLD bind() interpose (shim/getaddrinfo_shim.c, loaded through
// DYLD_INSERT_LIBRARIES). podnet's own env ABI (env.go:
// EnvPodIP / BindDisciplineEnv) is how the allocated /32 reaches it: the
// runtime injects it as K3SM_POD_IP, and the C shim reads it with getenv() at
// first bind. Once armed, the interpose rewrites a WILDCARD bind (0.0.0.0 or
// in6addr_any; TCP and UDP alike) at a port >= MinRewritablePort (1024) onto
// the pod's /32, so a workload that just does net.Listen(":8080") lands on
// its own pod IP instead of the shared wildcard. Several classes pass through
// UNREWRITTEN by design: a specific-address bind (the caller's explicit
// choice — including another pod's /32), a low port (<1024 — Darwin requires
// root for a SPECIFIC low-port bind but not a wildcard one, so rewriting
// would turn a working low-port workload into EACCES), port 0 (an ephemeral
// client bind whose destination this call cannot see), and a v6-only socket
// (IPV6_V6ONLY=1, which cannot accept a v4-mapped address). K3SM_POD_IP unset
// or unparseable disables the interpose entirely — fail-safe passthrough,
// with no error surfaced to the workload.
//
// This is a CORRECTNESS discipline, not an isolation boundary: nothing stops
// a process from an explicit bind onto another pod's /32 (the passthrough
// above), or from never loading the dylib at all (the DYLD-strip ceiling
// documented in the shim's banner). The `vm` RuntimeClass is the actual
// isolation boundary for an untrusted tenant (k3sm/docs/privilege-model.md); this
// discipline only keeps well-behaved same-node wildcard-binding workloads off
// each other's ports. The bind-interpose model above is host-process-only; a
// vm-RuntimeClass guest gets a NAT attachment instead (see "# Pod backends"
// below).
//
// # Pod backends: the path-selection fork (M5.1)
//
// Network serves two backends from one Allocator, chosen by the caller (runtimed,
// from the pod's RuntimeClass — apis runtimev1.HandlerVM => SANDBOX_BACKEND_VM):
//
//   - BackendHostProcess (Setup) — a native Darwin process. It gets a /32 lo0 alias
//     the host owns, and its own wildcard binds are rewritten onto it by the
//     bind() interpose (see "# Bind discipline" above). This path is unchanged.
//   - BackendVM (SetupGuest) — a Virtualization.framework micro-VM guest. A VZ guest
//     has its OWN network stack reached over a VZNATNetworkDeviceAttachment, so it
//     gets NO lo0 alias: aliasing the guest's IP on the host's lo0 would make the
//     host answer for it and blackhole same-node delivery. SetupGuest allocates the
//     pod IP (unified, leak-free IPAM) and returns a GuestNetwork (PodIP + NAT
//     gateway/subnet + cluster DNS VIP) for runtimed's VZ backend to APPLY. darwin-
//     net decides and allocates; it does NOT perform the live VZ attach (the DAG
//     keeps the VZ backend and the guest rootfs in runtimed) — the config flows
//     guest-ward as data. NAT, not bridged: a VZNATNetworkDeviceAttachment needs
//     only com.apple.security.virtualization, whereas a bridged/raw-vmnet attachment
//     needs the Apple-restricted com.apple.vm.networking entitlement (unobtainable).
//
// Teardown is shared: it releases the pod IP for both backends and removes the lo0
// alias ONLY for a host-process pod (a guest never had one).
//
// Lab-gated open questions (scaffolded, not built — they need a VZ-capable Mac):
//
//   - GUEST VIP REACHABILITY: can a guest behind a NAT attachment reach a ClusterIP
//     VIP that lives on a host lo0 alias? macOS NAT may only expose the gateway to
//     the guest and not weak-host-deliver a guest datagram to a host lo0-alias VIP.
//     If it does not, a host-side route or a NEW netd route-verb is needed (the netd
//     verb set has none today). OPEN — answer empirically on the lab Mac, then design.
//   - POD-IP vs NAT-IP: the guest's on-the-wire address is macOS-assigned (vmnet
//     DHCP) and differs from the allocated PodIP; reconciling them (so the guest is
//     reachable AT its pod IP, and so it can be a Service backend) is unsolved. For
//     M5 a guest pod is SAME-NODE-SCOPED and is NOT yet a cross-node Service backend
//     (its NAT-private IP is in no peer's mesh AllowedIPs).
//
// # Daemon boundary
//
// lo0 alias create/teardown is a privileged, root-only operation; in deployment
// it runs inside the root netd daemon. The real lo0AliasManager is kept in this
// package (not a cmd) only so the integration test can drive it directly under
// sudo. The pure Allocator carries no privilege and is the part reused wherever
// IPAM is needed.
package podnet
