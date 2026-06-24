# darwin-net — k3sm pod networking for macOS

`k3sm.io/darwin-net` gives Kubernetes Pods — native Darwin processes that share the host stack, with
**no network namespaces** — an IP each, plus Services and cross-node networking, for
[k3sm](https://github.com/k3sm-io/k3sm). It is the analog of flannel + kube-proxy + CNI:

- **netd** (root daemon) — `lo0` alias IPAM, the `pf` `k3sm` sub-anchor, `utun`.
- **proxy** — userspace Service proxy (VIP-owning sockets; kube-proxy is Linux-only).
- **wireguard** — `wireguard-go` userspace mesh carrying per-node pod CIDRs across Macs.
- **dnsshim** — `DYLD_INSERT_LIBRARIES` `getaddrinfo` → CoreDNS (macOS ignores `/etc/resolv.conf`).
- **podnet** — the CNI-seam `PodNetwork` interface the runtime calls during pod setup.

Shared types/gRPC live in [`k3sm.io/apis`](https://github.com/k3sm-io/apis).
See [DESIGN.md §5b](https://github.com/k3sm-io/k3sm/blob/main/docs/DESIGN.md).
