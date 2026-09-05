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
// the routable identity reachable over the wireguard mesh.
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
// # Bind discipline
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
// # Pod backends: the path-selection fork
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
// # Guest VIP reachability — ANSWERED, and it needs nothing (2026-08-31)
//
// This was an open question: can a guest behind a NAT attachment reach a
// ClusterIP VIP that lives on a host lo0 alias, or does macOS expose only the
// gateway to the guest? It was answered empirically by guest-networking lab
// findings, against a real lo0-alias VIP with a listener bound to the VIP itself
// (not the wildcard, so what XNU does with the destination address is observed
// rather than assumed), for both TCP and UDP/53.
//
// It delivers, and it delivers with NOTHING added. The measured baseline — no
// guest-side route for the service CIDR, host net.inet.ip.forwarding forced to 0,
// no host route for the VIP — already carries the packet to the VIP, and three
// further arrangements that added each of those in turn changed nothing. The
// guest's ordinary default NAT route is sufficient on its own; XNU weak-host-
// delivers to the lo0 alias. So the guest DNS VIP the guest resolv.conf points at
// (see pkg/dns.GuestResolvConf) needs no special handling either.
//
// Concretely, three things that were staged as fallbacks are NOT built and are not
// needed: no route data pushed into GuestNetwork, no new netd route verb (the netd
// verb set still has none), and no host forwarding or host route. The
// host also observes the guest's OWN vmnet lease as the source address — there is no
// NAT rewrite to the gateway on this path, which is what makes the two-address model
// below workable at all.
//
// Scope of the claim: one rig, one macOS version, one attachment type
// (VZNATNetworkDeviceAttachment). The live datapath legs stay lab-gated and are
// never auto-greened by this package's unit tests.
//
// # Pod IP vs lease address — the TWO-ADDRESS model
//
// The guest's on-the-wire address is macOS-assigned (vmnet DHCP) and differs from
// the allocated PodIP. These are not reconciled into one address, because they
// cannot be: the lease exists only after the guest boots, and the pod's published
// identity is baked before that. They are kept as two, with a single authority each.
//
//   - The podCIDR /32 (GuestNetwork.PodIP) is the PUBLISHED identity: status.podIP,
//     the EndpointSlice, cluster DNS. For a vm pod it is live on NO interface — the
//     host must never alias it, or the host would answer for the guest.
//   - The guest's DHCP lease is the LIVE TRANSPORT address: it is what host-to-guest
//     dials (probes, port-forward, the Service-proxy backend dial) must actually
//     target, and it is never published. The guest agent's Health lease report is its
//     single authority; darwin-net does not observe it.
//
// The Service-proxy seam where the two meet is RoutingTable.SetTransportOverrides in
// pkg/proxy: a published-to-live map consulted at the dial sites only, so the policy
// verdict and the endpoint identity keep using the published /32 while the packet
// follows the lease. A vm pod stays SAME-NODE-SCOPED and is not a cross-node Service
// backend: its lease address is in no peer's mesh AllowedIPs, and vmnet source-NAT is
// structurally incompatible with the mesh's symmetric AllowedIPs, so cross-node never
// "just works" and is not claimed.
//
// # Guest-to-guest — an observation, not a guarantee, in either direction
//
// On the tested rig, guest-to-guest was UNREACHABLE at both L2 and L3: ARP for a
// peer guest reached FAILED while ARP for the gateway resolved, ICMP saw 100% loss,
// and TCP was unreachable — with both guests independently proven live to the host in
// the same boot, so this is a controlled negative and not a broken guest.
//
// We neither rely on guest-to-guest reachability nor promise its absence. Apple
// documents no isolation guarantee for VZNATNetworkDeviceAttachment, so a claim that
// vm pods are isolated from one another would be a security claim resting on
// undocumented behaviour that a point release may change — and a design that assumed
// guests CAN reach each other would be equally unfounded here. Real tenant isolation
// is the vm boundary itself (k3sm/docs/privilege-model.md), not the NAT segment's
// topology. A bridged or file-handle attachment is a different question and is
// untested.
//
// # Daemon boundary
//
// lo0 alias create/teardown is a privileged, root-only operation; in deployment
// it runs inside the root netd daemon. The real lo0AliasManager is kept in this
// package (not a cmd) only so the integration test can drive it directly under
// sudo. The pure Allocator carries no privilege and is the part reused wherever
// IPAM is needed.
package podnet
