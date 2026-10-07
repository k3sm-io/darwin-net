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

package mesh

import (
	"context"
	"fmt"
	"net/netip"
)

// HostRoutes installs, verifies and removes the on-link /32 host route to a
// direct-link peer's address (`route add -host <peer> -interface <enX>`): the
// route that makes the kernel resolve the peer by ARP on the cable, and the next
// hop every direct /25 depends on. It drives the same routing socket and the same
// read-back as the mesh device, so "installed" always means "the kernel table
// holds it", never "the write was accepted". The root network helper owns it; the
// zero value uses the kernel table.
type HostRoutes struct {
	rt routeTable
}

// NewHostRoutes returns a HostRoutes over the kernel routing table.
func NewHostRoutes() *HostRoutes { return &HostRoutes{} }

func (h *HostRoutes) table() routeTable {
	if h.rt == nil {
		return kernelRouteTable{}
	}
	return h.rt
}

// hostRoute is the request for an on-link host route to peer on iface.
func hostRoute(peer netip.Addr, iface string) Route {
	return Route{Prefix: netip.PrefixFrom(peer.Unmap(), 32), Interface: iface}
}

// Ensure installs the host route to peer on iface (idempotent) and verifies it in
// the kernel table; a route the table does not hold afterwards is
// ErrRouteNotInstalled.
func (h *HostRoutes) Ensure(ctx context.Context, peer netip.Addr, iface string) error {
	want := hostRoute(peer, iface)
	ok, err := h.Present(ctx, peer, iface)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	report, addErr := h.table().Add(ctx, want)
	ok, err = h.Present(ctx, peer, iface)
	if err != nil {
		return err
	}
	if !ok {
		if addErr != nil {
			report = fmt.Sprintf("%s (error: %v)", report, addErr)
		}
		return fmt.Errorf("%w: host route %s absent from the kernel routing table%s", ErrRouteNotInstalled, want, routeReport(report))
	}
	return nil
}

// Remove deletes the host route to peer on iface (an absent route is not an
// error) and verifies it is gone.
func (h *HostRoutes) Remove(ctx context.Context, peer netip.Addr, iface string) error {
	return h.Delete(ctx, hostRoute(peer, iface))
}

// Present reports whether the kernel table holds the host route to peer on iface.
func (h *HostRoutes) Present(ctx context.Context, peer netip.Addr, iface string) (bool, error) {
	have, err := h.table().List(ctx)
	if err != nil {
		return false, fmt.Errorf("read back kernel routes: %w", err)
	}
	want := hostRoute(peer, iface)
	for _, k := range have {
		if holds(k, want) {
			return true, nil
		}
	}
	return false, nil
}

// List returns the kernel's IPv4 routes, for a caller that reconciles routes it
// does not own (the helper's start-up sweep of the reserved direct-link halves).
func (h *HostRoutes) List(ctx context.Context) ([]Route, error) {
	return h.table().List(ctx)
}

// Delete removes r — a route as List reported it, or one this type built — and
// verifies it is gone. Deleting an absent route is not an error.
func (h *HostRoutes) Delete(ctx context.Context, r Route) error {
	report, delErr := h.table().Delete(ctx, r)
	have, err := h.table().List(ctx)
	if err != nil {
		return fmt.Errorf("read back kernel routes: %w", err)
	}
	for _, k := range have {
		if holds(k, r) {
			if delErr != nil {
				report = fmt.Sprintf("%s (error: %v)", report, delErr)
			}
			return fmt.Errorf("route %s is still in the kernel routing table after its removal (%s)", r, report)
		}
	}
	return nil
}
