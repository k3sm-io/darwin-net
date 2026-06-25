# darwin-net — k3sm pod networking

Module **`k3sm.io/darwin-net`** (≈ flannel + kube-proxy + CNI): `netd` (lo0 alias IPAM, `pf` anchor,
`utun`), a userspace Service proxy, a `wireguard-go` mesh, a `getaddrinfo` DNS shim, and the
`PodNetwork` interface the runtime calls during pod setup.

> Roadmap & current phase: `docs/PHASES.md` (workspace matrix: `../ROADMAP.md`).

## Build / test (pure Go for now)
```sh
gofmt -l .
go vet ./...
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test ./...
go mod tidy
```

## Notes
- Prefer `golang.org/x/sys/unix` for darwin networking syscalls (utun, pf, lo0 aliases).
- Root-only operations (utun/pf/lo0 alias creation) live behind the `netd` daemon boundary.
- Shared types/protos go in `../apis` (not here).

## Standards
@docs/GO-STANDARDS.md
