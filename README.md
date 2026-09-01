# darwin-net

`darwin-net` is the pod-networking module of [k3sm](https://github.com/k3sm-io/k3sm), a
Kubernetes distribution for macOS on Apple Silicon. Kubernetes pods on k3sm are native Darwin
processes with no network namespace, so there is no kernel dataplane to hook the way flannel or
kube-proxy do on Linux. This module builds the same functions in userspace instead: an IP for
every pod (a `/32` alias on `lo0`), a Service proxy that load-balances ClusterIP and NodePort
traffic, a WireGuard mesh that connects pod networks across nodes, and a DNS shim that resolves
cluster names inside a pod process. It is the macOS analog of flannel, kube-proxy, and a CNI
plugin combined, built without a dependency on a container network namespace.

## Where this fits in the build

k3sm is built from four Go repositories. [`apis`](https://github.com/k3sm-io/apis) holds the
shared gRPC and CRD types and depends on nothing else. `darwin-net` and
[`runtimed`](https://github.com/k3sm-io/runtimed) each import `apis` and build independently of
each other — `darwin-net` handles pod networking, `runtimed` handles the sandboxed process
runtime. [`k3sm`](https://github.com/k3sm-io/k3sm) imports both to assemble the control plane, the
node agent, and the CLI into one binary.

```
apis  →  darwin-net, runtimed  →  k3sm
```

Nothing outside this repository depends on `darwin-net` reaching back into `k3sm` or `runtimed`;
the `PodNetwork` interface in `pkg/podnet` is the seam the runtime calls into, not the other way
around.

## Packages

| Package | What it does |
|---|---|
| [`pkg/podnet`](pkg/podnet) | IP-per-pod allocation: carves each node's `/24` out of the cluster pod CIDR, hands out `/32` addresses, and plumbs them onto `lo0`. Implements `PodNetwork`, the seam the runtime calls on pod setup and teardown. Also selects the guest-networking path for VM-backed pods. |
| [`pkg/proxy`](pkg/proxy) | The userspace Service proxy — one listening socket per ClusterIP:port, bound on a dedicated `lo0` alias, plus a NodePort listener where a port declares one. Load-balances to Ready backends from the Services and EndpointSlices APIs, with ClientIP session affinity and a NetworkPolicy L4 subset (see "NetworkPolicy" below). |
| [`pkg/mesh`](pkg/mesh) | A WireGuard mesh over a root-created `utun` that routes (never NATs) pod traffic between nodes. Peers, endpoints, and pod CIDRs come from the `MeshPeer` CRD in `apis`, watched and reconciled continuously. |
| [`pkg/dns`](pkg/dns) | Pod DNS: the pure-Go reference resolver (`ndots`/search-domain expansion) that the `getaddrinfo` shim mirrors, the per-pod DNS config the shim consumes, and `/etc/resolv.conf` rendering for Linux VM guests. |
| [`pkg/ingress`](pkg/ingress) | An in-process L7 HTTP(S) reverse proxy fronting the ClusterIP VIPs the Service proxy already owns — host/path routing, in-memory-only TLS termination, no bundled Traefik or nginx binary. |
| [`pkg/netbind`](pkg/netbind) | The shared listener-bind seam used by the Service proxy and the ingress proxy: bind directly, or ask the root daemon to bind and adopt the resulting socket over `SCM_RIGHTS`. |
| [`pkg/netd`](pkg/netd) | The logic of the root network daemon: `lo0` alias management, the WireGuard `utun` and its routes, the `pf` MSS-clamp anchor, and privileged port binds. See "Privilege split" below. |
| [`shim/getaddrinfo_shim.c`](shim/getaddrinfo_shim.c) | A `DYLD_INSERT_LIBRARIES` dylib, built with `clang` rather than cgo, that interposes `getaddrinfo`, `bind`, and `connect` inside a pod process: it resolves cluster names against the in-process cluster resolver, rewrites a wildcard bind onto the pod's own IP, and pins an outbound connection's source address for mesh-egress traffic. |

## Privilege split

macOS requires root for `lo0` alias creation, `utun` device creation, `pf` anchor loads, and
binding a port below 1024. `pkg/netd` is the only component in this repository that performs those
operations. It ships as a library, not a standalone binary: in deployment the single `k3sm` binary
re-execs itself in a "netd" mode and imports `netd.Server` to run it. Everything else —
`pkg/podnet`, `pkg/proxy`, `pkg/mesh`, `pkg/ingress` — runs as an unprivileged user and reaches the
daemon over a Unix socket when it needs a privileged operation.

The protocol (`pkg/netd/wire`) is a closed, versioned set of six verbs — `EnsureAlias`,
`RemoveAlias`, `ConfigureMesh`, `RemoveMesh`, `LoadPFAnchor`, `BindPort` — each carrying only typed
scalars (an IP, a port, a typed peer list). It never accepts raw route, `pf`, or WireGuard
configuration text, and it never accepts a filesystem path. The daemon does not trust its caller:
it re-derives and re-validates every parameter (CIDR containment, route sets, port authorization)
against the same logic in `pkg/podnet` and `pkg/mesh`, then renders the privileged artifacts
itself. Every connection is authenticated at accept time by peer credential (`LOCAL_PEERCRED`)
against the authorized service user; anything else is closed. The only file descriptor that ever
crosses the socket is the listening socket `BindPort` hands back to its caller over `SCM_RIGHTS` —
no descriptor is ever accepted inbound.

Each unprivileged consumer keeps a direct, non-daemon implementation of its own seam for a
run-as-root mode, and a daemon-backed implementation for normal deployment, selected with a single
constructor option.

## NetworkPolicy: what is actually enforced

`pkg/proxy` implements a NetworkPolicy ingress subset at its own accept paths. Because it evaluates
after the routing table picks a backend, it can only see traffic that transits a Service VIP — once
a pod has its own routable IP, direct pod-to-pod traffic (including all headless and StatefulSet
traffic, which resolves to pod IPs rather than a VIP) bypasses the proxy entirely and is not
covered. `ipBlock` peers, all egress rules, named ports, port ranges, and the rule's protocol field
are not evaluated and are widened rather than enforced strictly. This is a routing-time hint on
Service-mediated traffic, not a tenant isolation boundary; every pod on a node shares one process
user, so isolating an untrusted workload is a job for a separate, VM-backed runtime class, not for
this policy subset.

## Build and test

`darwin-net` is pure Go, built with `CGO_ENABLED=0`. It targets darwin/arm64 and Go 1.25.x.

```sh
gofmt -l .                  # must print nothing
go vet ./...
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test ./...
go mod tidy                 # must produce no diff
```

`hack/ci.sh` runs the same gate in one command, plus the license-header check:

```sh
hack/ci.sh
```

The `getaddrinfo` shim (`shim/getaddrinfo_shim.c`) is a separate C dylib, built with `clang` rather
than the Go toolchain:

```sh
hack/build-shim.sh
```

A handful of tests are root-gated (`lo0` alias churn, live `utun` bring-up) and are tagged
`integration`; they run under `sudo` with `-tags integration` and are skipped otherwise. Everything
else runs as an ordinary unit test, with no network access and no privilege.

Shared types and CRDs used by this repo live in
[`k3sm.io/apis`](https://github.com/k3sm-io/apis), not here.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow. Every commit must carry a
`Signed-off-by` line certifying the [Developer Certificate of Origin](DCO) — add it with
`git commit -s`. Licensed under the [Apache License 2.0](LICENSE); see also
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [SECURITY.md](SECURITY.md).
