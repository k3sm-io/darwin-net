# The egress datapath — host listener addresses (record)

This is a reference record of the production egress datapath: the chain a pod's
outbound request takes, and the complete set of host-side addresses/listeners
involved. It is derived directly from the current code, cited by file:line, and
is the named input for a future network-layer egress-enforcement design. It is
not itself an enforcement mechanism.

## The chain

1. **Name resolution.** A pod's `getaddrinfo` call is interposed by the DYLD
   shim (`shim/getaddrinfo_shim.c`), which reads its `netv1.DNSConfig` from the
   pod's environment and sends a DNS query over UDP to the cluster DNS VIP,
   port 53 (`pkg/dns/resolver.go:123` `serverAddr`; `pkg/dns/dnsconfig.go:26`
   `DefaultDNSPort = 53`). The Go reference resolver (`pkg/dns/resolver.go:100`
   `NewResolver`, `:141` `LookupHost`) mirrors the algorithm the C shim runs,
   including ndots/search expansion (`pkg/dns/expand.go`).
2. **VIP dial (ClusterIP/Service traffic).** An outbound connection to a
   ClusterIP:port is answered by the Service proxy's listener bound on that
   VIP's dedicated lo0 alias (`pkg/proxy/proxy.go:601` "ClusterIP stream
   listener on the specific lo0 alias address"; `pkg/proxy/proxy.go:661`
   `net.ListenPacket("udp", clusterAP.String())` for UDP), which then picks a
   Ready backend from the routing table and dials it.
3. **Backend dial, cross-node case (mesh egress source-pinning).** When the
   picked backend is on another node, the proxy's outbound dial is source-bound
   to this node's reserved mesh-egress `/32` so the return packet falls inside
   this node's wireguard `AllowedIPs` (`pkg/proxy/proxy.go:167`
   `WithMeshEgressSource`; the UDP relay does the same per-flow upstream bind,
   `pkg/proxy/doc.go:217`). Without this pinning, an unscoped egress source is
   silently dropped by wireguard on the far side (one-way blackhole).
4. **Direct pod-to-pod traffic** (not VIP-mediated) never enters the proxy: a
   same-node dial to another pod's `/32` lo0 alias stays on loopback, and a
   cross-node dial to a peer's pod `/24` is carried by the kernel routes the
   mesh installs on the utun (`pkg/mesh/plan.go:105` `RouteSet`).

## The enumerated host address/listener set

- **Per-Service ClusterIP VIP aliases on lo0** — one `/32` alias per ClusterIP,
  created by the proxy's `aliasManager.Ensure` (`pkg/proxy/alias.go:79`
  `lo0AliasManager.Ensure`) before the listener binds. The TCP listener binds
  the specific `clusterIP:port` (`pkg/proxy/proxy.go:601`); the UDP relay binds
  the same VIP via `net.ListenPacket` (`pkg/proxy/proxy.go:661`).
- **Per-node `*:NodePort` wildcard listener(s)** — bound on the wildcard
  address, one per Service port that declares a NodePort, TCP only
  (`pkg/proxy/proxy.go:700` `net.Listen("tcp", nodeAddr)`).
- **The cluster DNS VIP**, `10.43.0.10` by default
  (`pkg/dns/dnsconfig.go:38` `DefaultDNSVIP`), port 53 TCP and UDP. This
  address is explicitly exempted from proxy ownership — no lo0 alias, no
  proxy-owned socket — because a node-local resolver binds it directly
  (`pkg/proxy/proxy.go:200` `WithInfraVIPExemptions`).
- **Each pod's own `/32` lo0 alias** — allocated from the node's pod `/24` and
  aliased on lo0 for a host-process pod only; a vm-RuntimeClass guest gets none
  (`pkg/podnet/podnet.go:168` `Network.Setup`, `:195`
  `n.alias.Ensure(ctx, ip)`; `pkg/podnet/alias.go:78`
  `lo0AliasManager.Ensure`).
- **The node's mesh-egress `/32`** — the first host address (`.1`) of the
  node's pod `/24`, reserved from pod allocation and used as the source
  address for cross-node backend dials (`pkg/podnet/meshegress.go:39`
  `MeshEgressIP`; `pkg/podnet/allocator.go:135` reservation of `.1`;
  `pkg/proxy/proxy.go:167` `WithMeshEgressSource` binds the proxy's dialer to
  it).
- **The node's mesh-link `/32`** — the last address (`.255`) of the node's pod
  `/24`, assigned as the utun's own point-to-point interface address
  (`pkg/podnet/meshegress.go` `MeshLinkIP`; `pkg/mesh/device_wireguard.go`
  `WGDevice.Up`). It reuses the address the allocator already reserves as the
  broadcast address, so it costs no pod capacity. macOS will not install an
  interface-bound route on an addressless utun, so this address is what makes
  the per-peer routes installable; the kernel also selects it as the source for
  host traffic to a peer pod `/24` that binds no source of its own, which is why
  it is drawn from the node's own `/24` (inside every peer's `AllowedIPs`).
- **The utun device** — the wireguard mesh interface that carries cross-node
  pod `/24` traffic per the per-peer kernel routes computed by
  `pkg/mesh/plan.go` `RouteSet` and verified against the kernel routing table by
  `pkg/mesh/device_wireguard.go` `WGDevice.reconcileRoutes`; it never carries
  this node's own `/24` or the `100.64.0.0/10` cluster aggregate (loopback
  traffic stays on lo0).

## Purpose

This record exists to give a future PF-based egress-enforcement effort a
precise, code-grounded list of the addresses and listeners the current
datapath touches, so that enforcement work starts from what the code actually
does rather than from an assumption about it.
