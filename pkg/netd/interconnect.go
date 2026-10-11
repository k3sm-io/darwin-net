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

package netd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/netd/wire"
	"k3sm.io/darwin-net/pkg/podnet"
)

// interconnectCIDR is the one connected subnet every interconnect address lives
// in (netv1alpha1.InterconnectCIDR).
var interconnectCIDR = netip.MustParsePrefix(netv1alpha1.InterconnectCIDR)

// interconnectBits is the prefix length the daemon gives a slot's alias: slot 0
// carries the node's connected /24 (the route every interconnect address rides),
// slots 1..7 are /32 aliases inside it. There is never a route of its own.
func interconnectBits(slot int) int {
	if slot == 0 {
		return interconnectCIDR.Bits()
	}
	return 32
}

// netmaskOf renders a prefix length as the dotted netmask ifconfig takes.
func netmaskOf(bits int) string {
	m := ^uint32(0) << (32 - bits)
	return netip.AddrFrom4([4]byte{byte(m >> 24), byte(m >> 16), byte(m >> 8), byte(m)}).String()
}

// InterconnectAddrs reads bridge0's IPv4 addresses. A host without bridge0 (the
// Thunderbolt Bridge was deleted) yields an error wrapping
// wire.ErrInterconnectNoBridge.
func (a *darwinApplier) InterconnectAddrs(ctx context.Context) (map[netip.Addr]bool, error) {
	out, err := a.output(ctx, "ifconfig", bridgeIface)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", wire.ErrInterconnectNoBridge, err)
	}
	addrs, _ := parseIfconfig(out)
	return addrs, nil
}

// AddInterconnectAlias puts addr on bridge0 with a bits-long netmask:
// `ifconfig bridge0 inet <addr> netmask <mask> alias`, the form the B519 rig
// proved. The interface is fixed; no route is added. It re-checks the server's
// policy shape (an interconnect address, a /24 or /32) so no other address can
// reach bridge0 through this call.
func (a *darwinApplier) AddInterconnectAlias(ctx context.Context, addr netip.Addr, bits int) error {
	if !interconnectCIDR.Contains(addr) || (bits != 32 && bits != interconnectCIDR.Bits()) {
		return fmt.Errorf("%w: %s/%d is not an interconnect alias", ErrPolicy, addr, bits)
	}
	if err := a.command(ctx, "ifconfig", bridgeIface, "inet", addr.String(), "netmask", netmaskOf(bits), "alias"); err != nil {
		return fmt.Errorf("add interconnect alias %s/%d on %s: %w", addr, bits, bridgeIface, err)
	}
	return nil
}

// RemoveInterconnectAlias removes addr from bridge0: `ifconfig bridge0 -alias
// <addr>`. It touches only an interconnect address and never bridge0's
// membership.
func (a *darwinApplier) RemoveInterconnectAlias(ctx context.Context, addr netip.Addr) error {
	if !interconnectCIDR.Contains(addr) {
		return fmt.Errorf("%w: %s is not an interconnect address", ErrPolicy, addr)
	}
	if err := a.command(ctx, "ifconfig", bridgeIface, "-alias", addr.String()); err != nil {
		return fmt.Errorf("remove interconnect alias %s from %s: %w", addr, bridgeIface, err)
	}
	return nil
}

// interconnectErr builds a rejection that names its refusal in Response.Reason.
func (s *Server) interconnectErr(err error) wire.Response {
	resp := s.errResp(err.Error())
	resp.Reason = wire.ReasonOf(err)
	return resp
}

// interconnectTarget validates slot and derives its address from the daemon's
// own adopted identity: the slot is 0..MaxInterconnectSlot, the identity is
// confirmed (adopted from a ConfigureMesh or restored), and its cluster index is
// within 0..MaxInterconnectNodeIndex. Nothing the client sent but the slot
// enters the derivation.
func (s *Server) interconnectTarget(slot int) (netip.Addr, error) {
	if slot < 0 || slot > netv1alpha1.MaxInterconnectSlot {
		return netip.Addr{}, fmt.Errorf("%w: %w: slot %d is outside 0..%d", ErrPolicy, wire.ErrInterconnectSlotOutOfRange, slot, netv1alpha1.MaxInterconnectSlot)
	}
	idx, err := s.interconnectIndex()
	if err != nil {
		return netip.Addr{}, err
	}
	addr, err := netv1alpha1.InterconnectSlotAddress(idx, slot)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %w: %v", ErrPolicy, wire.ErrInterconnectIndexOutOfRange, err)
	}
	return addr, nil
}

// interconnectIndex returns the cluster index of the adopted node pod CIDR, or a
// named refusal: no adopted identity yet (never a default or zero index), or an
// index beyond MaxInterconnectNodeIndex.
func (s *Server) interconnectIndex() (int, error) {
	s.mu.RLock()
	node, confirmed := s.nodePodCIDR, s.identityConfirmed
	s.mu.RUnlock()
	if !confirmed {
		return 0, fmt.Errorf("%w: %w: a ConfigureMesh carrying the node pod CIDR must come first", ErrPolicy, wire.ErrInterconnectIdentityUnadopted)
	}
	idx, err := podnet.NodeIndex(s.cfg.ClusterAggregate, node)
	if err != nil {
		return 0, fmt.Errorf("%w: node %s has no cluster index: %v", ErrPolicy, node, err)
	}
	if idx > netv1alpha1.MaxInterconnectNodeIndex {
		return 0, fmt.Errorf("%w: %w: node %s has cluster index %d, beyond %d", ErrPolicy, wire.ErrInterconnectIndexOutOfRange, node, idx, netv1alpha1.MaxInterconnectNodeIndex)
	}
	return idx, nil
}

// handleEnsureInterconnectAlias puts one slot's derived address on bridge0. It is
// idempotent against the kernel, not only the ledger: an address already on
// bridge0 is recorded as owned with no command, and an owned address that has
// gone missing is added again. The slot bound (0..7) bounds bridge0 at 8
// interconnect aliases.
func (s *Server) handleEnsureInterconnectAlias(ctx context.Context, args *wire.InterconnectAliasArgs) wire.Response {
	if args == nil {
		return s.errResp("ensureInterconnectAlias: missing args")
	}
	addr, err := s.interconnectTarget(args.Slot)
	if err != nil {
		s.log.Warn("netd: interconnect alias refused", "slot", args.Slot, "err", err)
		return s.interconnectErr(err)
	}
	s.icMu.Lock()
	defer s.icMu.Unlock()
	present, err := s.priv.InterconnectAddrs(ctx)
	if err != nil {
		s.log.Warn("netd: interconnect alias refused", "slot", args.Slot, "err", err)
		return s.interconnectErr(fmt.Errorf("ensureInterconnectAlias: %w", err))
	}
	bits := interconnectBits(args.Slot)
	if present[addr] {
		s.log.Debug("netd: interconnect alias already on bridge0", "slot", args.Slot, "ip", addr.String())
	} else {
		if err := s.priv.AddInterconnectAlias(ctx, addr, bits); err != nil {
			s.log.Warn("netd: interconnect alias failed", "slot", args.Slot, "ip", addr.String(), "err", err)
			return s.errResp(fmt.Sprintf("ensureInterconnectAlias: %v", err))
		}
		s.log.Info("netd: interconnect alias added", "slot", args.Slot, "ip", addr.String(), "bits", bits, "iface", bridgeIface)
	}
	s.setOwned(args.Slot, addr)
	resp := s.okResp()
	resp.InterconnectIP = addr.String()
	return resp
}

// handleRemoveInterconnectAlias removes one slot's alias from bridge0. A slot the
// daemon does not own is a no-op: it never removes an alias it did not create or
// adopt. Slot 0 is refused while any slot 1..7 alias is owned, because those /32s
// ride slot 0's connected /24. An alias already gone is success.
func (s *Server) handleRemoveInterconnectAlias(ctx context.Context, args *wire.InterconnectAliasArgs) wire.Response {
	if args == nil {
		return s.errResp("removeInterconnectAlias: missing args")
	}
	addr, err := s.interconnectTarget(args.Slot)
	if err != nil {
		s.log.Warn("netd: interconnect alias removal refused", "slot", args.Slot, "err", err)
		return s.interconnectErr(err)
	}
	s.icMu.Lock()
	defer s.icMu.Unlock()
	s.mu.RLock()
	owned, had := s.icOwned[args.Slot]
	var riders []int
	for slot := range s.icOwned {
		if slot != 0 {
			riders = append(riders, slot)
		}
	}
	s.mu.RUnlock()
	if !had || owned != addr {
		s.log.Debug("netd: interconnect alias not owned; nothing removed", "slot", args.Slot, "ip", addr.String())
		resp := s.okResp()
		resp.InterconnectIP = addr.String()
		return resp
	}
	if args.Slot == 0 && len(riders) > 0 {
		slices.Sort(riders)
		err := fmt.Errorf("%w: %w: slots %v are still owned", ErrPolicy, wire.ErrInterconnectTeardownOrder, riders)
		s.log.Warn("netd: interconnect alias removal refused", "slot", 0, "err", err)
		return s.interconnectErr(err)
	}
	present, err := s.priv.InterconnectAddrs(ctx)
	if err != nil {
		// No bridge0, no alias on it.
		s.log.Warn("netd: bridge0 is unreadable; an owned interconnect alias is taken as gone", "slot", args.Slot, "ip", addr.String(), "err", err)
		present = nil
	}
	if present[addr] {
		if err := s.priv.RemoveInterconnectAlias(ctx, addr); err != nil {
			again, rerr := s.priv.InterconnectAddrs(ctx)
			if rerr == nil && again[addr] {
				s.log.Warn("netd: interconnect alias removal failed", "slot", args.Slot, "ip", addr.String(), "err", err)
				return s.errResp(fmt.Sprintf("removeInterconnectAlias: %v", err))
			}
			s.log.Warn("netd: interconnect alias removal reported an error but the alias is gone", "slot", args.Slot, "ip", addr.String(), "err", err)
		}
		s.log.Info("netd: interconnect alias removed", "slot", args.Slot, "ip", addr.String(), "iface", bridgeIface)
	} else {
		s.log.Debug("netd: owned interconnect alias already gone", "slot", args.Slot, "ip", addr.String())
	}
	s.dropOwned(args.Slot)
	resp := s.okResp()
	resp.InterconnectIP = addr.String()
	return resp
}

// setOwned records slot's alias as the daemon's and persists the ledger.
// s.icMu must be held.
func (s *Server) setOwned(slot int, addr netip.Addr) {
	s.mu.Lock()
	s.icOwned[slot] = addr
	snap := ownedEntries(s.icOwned)
	s.mu.Unlock()
	s.persistInterconnect(snap)
}

// dropOwned forgets slot's alias and persists the ledger. s.icMu must be held.
func (s *Server) dropOwned(slot int) {
	s.mu.Lock()
	delete(s.icOwned, slot)
	snap := ownedEntries(s.icOwned)
	s.mu.Unlock()
	s.persistInterconnect(snap)
}

// interconnectEntry is one owned alias in the persisted ledger.
type interconnectEntry struct {
	Slot    int    `json:"slot"`
	Address string `json:"address"`
}

// interconnectLedger is the persisted shape of the owned interconnect aliases.
type interconnectLedger struct {
	Aliases []interconnectEntry `json:"aliases"`
}

// ownedEntries renders the owned set as ledger entries, by slot.
func ownedEntries(owned map[int]netip.Addr) []interconnectEntry {
	out := make([]interconnectEntry, 0, len(owned))
	for slot, addr := range owned {
		out = append(out, interconnectEntry{Slot: slot, Address: addr.String()})
	}
	slices.SortFunc(out, func(a, b interconnectEntry) int { return a.Slot - b.Slot })
	return out
}

// persistInterconnect writes the ledger when Config.InterconnectStatePath is
// set. A failure is logged, never fatal: after a restart the reconcile would
// remove the unrecorded alias, which is the safe direction (the alias is one of
// this node's own derived addresses, and k3sm ensures it again).
func (s *Server) persistInterconnect(entries []interconnectEntry) {
	if s.cfg.InterconnectStatePath == "" {
		return
	}
	raw, err := json.Marshal(interconnectLedger{Aliases: entries})
	if err == nil {
		err = writeFileAtomic(s.cfg.InterconnectStatePath, ".interconnect-*", append(raw, '\n'))
	}
	if err != nil {
		s.log.Error("netd: persisting the owned interconnect aliases failed (a helper restart will remove the unrecorded ones)",
			"path", s.cfg.InterconnectStatePath, "err", err)
	}
}

// restoreInterconnect reads the ledger and keeps only the entries that are
// exactly derived[slot]: an entry from another identity, a bad slot, or a
// malformed address is dropped. It is fail-open like restoreIdentity: an absent,
// unreadable or malformed file is an empty ledger.
func (s *Server) restoreInterconnect(derived map[int]netip.Addr) map[int]netip.Addr {
	owned := make(map[int]netip.Addr)
	path := s.cfg.InterconnectStatePath
	if path == "" {
		return owned
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.log.Warn("netd: reading the owned interconnect aliases failed (treating none as owned)", "path", path, "err", err)
		}
		return owned
	}
	var l interconnectLedger
	if err := json.Unmarshal(raw, &l); err != nil {
		s.log.Warn("netd: the owned interconnect aliases file is malformed (treating none as owned)", "path", path, "err", err)
		return owned
	}
	for _, e := range l.Aliases {
		addr, err := netip.ParseAddr(e.Address)
		if want, ok := derived[e.Slot]; err != nil || !ok || addr != want {
			s.log.Warn("netd: dropping an owned interconnect alias that is not this node's derived address", "slot", e.Slot, "address", e.Address)
			continue
		}
		owned[e.Slot] = addr
	}
	return owned
}

// reconcileInterconnectAtStart restores the owned ledger and removes, from
// bridge0, every address of this node's derived set {InterconnectSlotAddress(idx,
// s) : s in 0..7} that is present and not owned. Its blast radius is that set and
// nothing else: no other 169.254.0.0/24 address, not the self-assigned 169.254.x.y,
// no other interface, never bridge0's membership, never a route. The /32s go
// first and slot 0 last, and slot 0 stays while an owned /32 rides it. A removal
// that fails (including macOS 27's undeletable cloned route, "not in table") is
// logged and the reconcile continues; nothing is ever re-added over it. It needs
// an adopted identity; without one it does nothing.
func (s *Server) reconcileInterconnectAtStart(ctx context.Context) {
	s.icMu.Lock()
	defer s.icMu.Unlock()
	idx, err := s.interconnectIndex()
	if err != nil {
		s.log.Info("netd: no interconnect reconcile at start", "reason", err)
		s.mu.Lock()
		clear(s.icOwned)
		s.mu.Unlock()
		s.persistInterconnect(nil)
		return
	}
	derived := make(map[int]netip.Addr, netv1alpha1.MaxInterconnectSlot+1)
	for slot := 0; slot <= netv1alpha1.MaxInterconnectSlot; slot++ {
		addr, err := netv1alpha1.InterconnectSlotAddress(idx, slot)
		if err != nil {
			s.log.Warn("netd: no interconnect reconcile at start", "err", err)
			return
		}
		derived[slot] = addr
	}
	owned := s.restoreInterconnect(derived)
	s.mu.Lock()
	s.icOwned = owned
	snap := ownedEntries(owned)
	s.mu.Unlock()
	s.persistInterconnect(snap)

	present, err := s.priv.InterconnectAddrs(ctx)
	if err != nil {
		s.log.Info("netd: no interconnect reconcile at start", "err", err)
		return
	}
	for slot := netv1alpha1.MaxInterconnectSlot; slot >= 0; slot-- {
		addr := derived[slot]
		if !present[addr] {
			continue
		}
		if _, mine := owned[slot]; mine {
			continue
		}
		if slot == 0 && ownsRider(owned, present) {
			s.log.Warn("netd: keeping an unowned slot-0 interconnect alias while an owned /32 rides it", "ip", addr.String())
			continue
		}
		if err := s.priv.RemoveInterconnectAlias(ctx, addr); err != nil {
			s.log.Warn("netd: removing a stale interconnect alias failed (left in place, never re-added over)", "slot", slot, "ip", addr.String(), "err", err)
			continue
		}
		s.log.Info("netd: removed a stale interconnect alias", "slot", slot, "ip", addr.String(), "iface", bridgeIface)
	}
}

// ownsRider reports whether an owned slot 1..7 alias is present on bridge0.
func ownsRider(owned map[int]netip.Addr, present map[netip.Addr]bool) bool {
	for slot, addr := range owned {
		if slot != 0 && present[addr] {
			return true
		}
	}
	return false
}

// writeFileAtomic writes data to path through a 0600 temp file (pattern) in the
// same directory and a rename, the identity file's discipline.
func writeFileAtomic(path, pattern string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), pattern)
	if err != nil {
		return fmt.Errorf("create temp beside %s: %w", path, err)
	}
	tmp := f.Name()
	defer func() {
		// A no-op once the rename succeeded (the name is gone by then).
		_ = os.Remove(tmp)
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmp, path, err)
	}
	return nil
}
