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

package proxy

import (
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// maxUDPFlows bounds the relay's per-VIP flow table. Same-node pods share one
// trust domain with no per-pod uid isolation, so a single pod cycling ephemeral
// source ports must not exhaust file descriptors and goroutines for every Service
// the proxy owns. On saturation a NEW flow is dropped (a live flow is never
// evicted); the cap is generous so legitimate fan-in is unaffected.
const maxUDPFlows = 8192

// maxUDPFlowsPerSource is the per-VIP fair-share sub-cap: no single source IP may
// hold more than this many concurrent flows PER VIP. It is strictly less than the
// per-VIP maxUDPFlows so the fair share is not vacuous — one same-node pod cycling
// ephemeral source ports cannot monopolize a VIP's whole flow table and starve
// every other pod's access to that Service (the caps mirror flows membership, so a
// dropped flow never counted and a reaped flow un-counts). Fairness is PER VIP: a
// pod fanning across N VIPs can still reach the relay-global fd budget (udpBudget);
// a per-source-GLOBAL variant is a follow-up (see doc.go).
const maxUDPFlowsPerSource = maxUDPFlows / 4

// maxUDPDatagram is the read buffer size for one datagram. A datagram socket
// discards any bytes beyond the supplied buffer, so it is sized to the maximum
// IPv4 UDP payload to avoid truncating a large datagram. One buffer is held per
// live flow reader, so worst-case buffer memory is bounded by maxUDPFlows.
const maxUDPDatagram = 65535

// udpSaturationWarnInterval throttles the flow-table-saturation Warn so a pod
// flooding new flows logs at most once per interval, not once per dropped
// datagram.
const udpSaturationWarnInterval = 10 * time.Second

// udpBudget is the relay-GLOBAL cap on concurrent UDP upstream sockets across ALL
// per-VIP relays. The relays run as concurrent per-VIP dispatchers, so this MUST be
// an atomic test-and-set: a plain counter would let two relays both observe "under
// budget" and overshoot the shared fd slice. It is a leaf in the lock order —
// reserve/release take no other lock and never call back into a relay — so the
// relay's mu → budget is a strict, deadlock-free ordering (a relay may call
// reserve/release while holding its own mu). max is set once at construction and
// read-only; n is the live count of reserved slots.
type udpBudget struct {
	n   atomic.Int64
	max int64
}

// reserve admits one upstream socket iff the live count is below max, returning
// true and incrementing the count on success and false without mutating on refusal.
// The CAS loop makes the test-and-increment atomic across concurrent per-VIP relays.
func (b *udpBudget) reserve() bool {
	for {
		cur := b.n.Load()
		if cur >= b.max {
			return false
		}
		if b.n.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// release returns one reserved slot to the budget. It MUST be called exactly once
// per successful reserve (i.e. exactly once per flow removed from a relay's table),
// so the global count is an exact function of live flows.
func (b *udpBudget) release() { b.n.Add(-1) }

// udpFlow is one client→backend datagram flow: a connected upstream socket to the
// backend picked once for this client 5-tuple, plus the client address responses
// are written back to. lastActivity drives idle GC.
//
// Locking discipline: lastActivity is guarded by udpRelay.mu — it is written by
// the dispatcher on a client→upstream datagram and by the reader on an
// upstream→client datagram, and read by the sweeper. upstream, clientAddr, and
// srcIP are set once before the reader goroutine is started and never mutated, so
// the reader reads them without the lock (the goroutine-start happens-before covers
// it); srcIP is read again under mu by the sweeper/Close to un-count the flow. srcIP
// is the parsed source IP of clientAddr — the per-source fair-share bucket key —
// stored on the flow so a removal path un-counts the exact bucket the insert counted.
type udpFlow struct {
	upstream     *net.UDPConn
	clientAddr   net.Addr
	srcIP        netip.Addr
	lastActivity time.Time
}

// udpRelay is the connectionless ClusterIP UDP data path — the macOS-native analog
// of kube-proxy's userspace UDP proxy. One dispatcher goroutine reads datagrams on
// the VIP PacketConn and, per client 5-tuple, selects a backend ONCE (via
// RoutingTable.Pick — the single iTP/round-robin/fail-open selector; the relay
// never re-picks per datagram), opens a connected per-flow upstream socket,
// forwards the datagram, and spawns one reader goroutine that writes each backend
// response back to the client with the VIP as the source. A sweeper goroutine
// idle-GCs flows. Like the TCP splice the relay re-originates traffic (Cluster
// policy): it does NOT preserve the client pod source IP, and on a multi-node mesh
// each upstream socket is source-bound to the node's mesh-egress /32 so the
// wireguard return path is not blackholed.
//
// Non-reflection invariant: a backend response is written back ONLY to the client
// address the inbound datagram carried (conn.WriteTo to fl.clientAddr). The relay
// does not self-enforce non-reflection — that safety rests on the same anti-spoofing
// the TCP splice and upstream kube-proxy userspace already assume: unprivileged pods
// cannot open raw sockets to forge an L3 source, and wireguard's symmetric AllowedIPs
// constrain every cross-node source to the sending node's pod CIDR.
//
// Fair-share + budget (B48): the per-VIP cap (maxUDPFlows) bounds total flows but is
// not a per-source quota, so B48 adds two more admission gates. perSourceCap
// (maxUDPFlowsPerSource) bounds any single source IP's flows PER VIP so one pod
// cycling ephemeral ports cannot monopolize a VIP's table; budget (a shared
// udpBudget) bounds concurrent upstream sockets across ALL relays so the relay
// subsystem cannot exhaust the co-resident control plane's fds. perSource and the
// budget are an EXACT function of flows membership: both are incremented only at the
// authoritative insert and decremented only at a flow delete (see upstreamFor,
// sweepExpired, Close) — no admission early-return ever touches them, so the counts
// never drift and the caps can never silently stop firing.
//
// Locking discipline: mu guards flows, perSource, closed, and each flow's
// lastActivity. The dispatcher is the SOLE inserter; the sweeper and Close are the
// only removers; readers only update lastActivity. Pick and all socket I/O run
// OUTSIDE mu (Pick has its own lock; a blocking Read/Write must never hold mu). The
// budget is a leaf: reserve/release may be called while holding mu (mu → budget is
// the fixed order) and never re-enter the relay. Close joins the dispatcher, the
// sweeper, and every reader through wg before returning, so teardown strands no
// goroutine.
type udpRelay struct {
	conn         net.PacketConn
	key          PortKey
	table        *RoutingTable
	meshEgress   netip.Addr
	idleTimeout  time.Duration
	perSourceCap int
	budget       *udpBudget
	log          *slog.Logger

	mu     sync.Mutex
	closed bool
	flows  map[string]*udpFlow
	// perSource counts live flows per source IP, guarded by mu. It mirrors flows
	// exactly (summed, it equals len(flows)); an entry is pruned at zero so an idle
	// source leaks no map slot. It is the per-source fair-share sub-cap's counter.
	perSource map[netip.Addr]int

	done chan struct{}
	wg   sync.WaitGroup
}

// newUDPRelay builds a relay serving conn (the VIP datagram socket) for key,
// selecting backends from table. meshEgress, when valid, source-binds each
// per-flow upstream socket (the multi-node mesh path); the zero Addr keeps the
// kernel's default source selection (single node). idleTimeout is the flow GC
// idle timeout. perSourceCap bounds any one source IP's concurrent flows on this
// VIP (the fair share); budget is the shared relay-global upstream-socket budget —
// a nil budget is defensively replaced with a private one sized to the per-VIP cap
// so reserve/release never nil-panic (no cross-VIP coupling, the pre-B48 bound).
// Call start to run it and Close to tear it down.
func newUDPRelay(conn net.PacketConn, key PortKey, table *RoutingTable, meshEgress netip.Addr, idleTimeout time.Duration, perSourceCap int, budget *udpBudget, log *slog.Logger) *udpRelay {
	if budget == nil {
		budget = &udpBudget{max: maxUDPFlows}
	}
	return &udpRelay{
		conn:         conn,
		key:          key,
		table:        table,
		meshEgress:   meshEgress,
		idleTimeout:  idleTimeout,
		perSourceCap: perSourceCap,
		budget:       budget,
		log:          log,
		flows:        make(map[string]*udpFlow),
		perSource:    make(map[netip.Addr]int),
		done:         make(chan struct{}),
	}
}

// start launches the dispatcher and the idle-flow sweeper. Both are joined by
// Close.
func (r *udpRelay) start() {
	r.wg.Add(2)
	go r.dispatch()
	go r.sweep()
}

// dispatch is the single reader of the VIP socket: for each datagram it resolves
// the client's flow (creating it on first sight) and forwards the payload to the
// connected upstream socket. It returns when conn is closed (Close), draining the
// goroutine.
func (r *udpRelay) dispatch() {
	defer r.wg.Done()
	buf := make([]byte, maxUDPDatagram)
	var lastWarn time.Time
	for {
		n, clientAddr, err := r.conn.ReadFrom(buf)
		if err != nil {
			return // VIP socket closed → shutting down
		}
		up := r.upstreamFor(clientAddr, &lastWarn)
		if up == nil {
			continue // no backend, saturated, dial failed, or shutting down: drop
		}
		if _, err := up.Write(buf[:n]); err != nil {
			r.log.Debug("udp relay forward upstream", "vip", r.key.String(), "err", err)
		}
	}
}

// upstreamFor returns the connected upstream socket for clientAddr's flow,
// creating the flow on first sight: it picks a backend ONCE (RoutingTable.Pick),
// dials a connected upstream socket source-bound to the mesh-egress address when
// set, records the flow, and starts its reader goroutine. It returns nil — the
// datagram is dropped — when there is no Ready backend, an admission cap is reached,
// the dial fails, or the relay is closing. Pick and DialUDP run outside mu; only the
// map lookup and insert hold it. lastWarn is the dispatcher-local saturation-warn
// throttle (the dispatcher is the only caller).
//
// Admission is a first-lock best-effort reject → dial → second-lock authoritative
// admit. The FIRST lock is a read-only early reject (per-VIP full OR this source at
// its per-VIP cap) that skips a doomed dial but reserves and increments NOTHING. The
// SECOND lock, at the insert site, is authoritative: it re-checks per-VIP, then
// per-source, then reserves the global fd budget LAST (so a successful reservation is
// always immediately paired with an insert — nothing can fail after it, so there is
// no release-on-reject path). The counters (perSource, budget) are incremented ONLY
// here at the successful insert and decremented ONLY at a flow delete, so they are an
// exact function of flows membership. EVERY second-lock rejection Close()s the dialed
// socket so a rejected upstream fd never leaks.
func (r *udpRelay) upstreamFor(clientAddr net.Addr, lastWarn *time.Time) *net.UDPConn {
	clientKey := clientAddr.String()
	srcIP := srcIPOf(clientAddr)

	r.mu.Lock()
	if fl := r.flows[clientKey]; fl != nil {
		fl.lastActivity = time.Now()
		up := fl.upstream
		r.mu.Unlock()
		return up
	}
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	// Best-effort early reject: skip the dial when this VIP's table is full or this
	// source is already at its per-VIP fair-share cap. Read-only — no reservation, no
	// increment — the second lock is authoritative, so a race here costs at worst a
	// wasted dial+close, never an over-admit.
	perVIPFull := len(r.flows) >= maxUDPFlows
	perSourceFull := r.perSource[srcIP] >= r.perSourceCap
	if perVIPFull || perSourceFull {
		r.mu.Unlock()
		if time.Since(*lastWarn) >= udpSaturationWarnInterval {
			*lastWarn = time.Now()
			if perVIPFull {
				r.log.Warn("udp relay flow table saturated; dropping new flow", "vip", r.key.String(), "maxFlows", maxUDPFlows)
			} else {
				r.log.Warn("udp relay per-source flow cap reached; dropping new flow", "vip", r.key.String(), "src", srcIP.String(), "perSourceCap", r.perSourceCap)
			}
		}
		return nil
	}
	r.mu.Unlock()

	be, err := r.table.Pick(r.key)
	if err != nil {
		r.log.Debug("udp relay no backend", "vip", r.key.String(), "err", err)
		return nil
	}
	var laddr *net.UDPAddr
	if r.meshEgress.IsValid() {
		// Re-originate from the node's mesh-egress /32 so a cross-node (utun) reply
		// falls inside this node's wireguard AllowedIPs and is not blackholed. A
		// *net.TCPAddr LocalAddr (p.dialer's) cannot dial "udp", so the relay binds a
		// *net.UDPAddr built from this Addr instead of reusing the TCP dialer.
		laddr = &net.UDPAddr{IP: r.meshEgress.AsSlice()}
	}
	raddr := net.UDPAddrFromAddrPort(be.Addr())
	up, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		r.log.Debug("udp relay dial backend", "vip", r.key.String(), "backend", raddr.String(), "err", err)
		return nil
	}

	r.mu.Lock()
	if r.closed {
		// Lost the race with Close (which set closed under mu): don't strand the
		// just-dialed socket or spawn a reader that Close would never join. Pre-insert:
		// nothing was reserved or counted, so there is nothing to release.
		r.mu.Unlock()
		_ = up.Close()
		return nil
	}
	// Authoritative admit. Re-check per-VIP then per-source (the first-lock read raced
	// the dial); on either rejection close the dialed socket so its fd does not leak.
	if len(r.flows) >= maxUDPFlows || r.perSource[srcIP] >= r.perSourceCap {
		r.mu.Unlock()
		_ = up.Close()
		return nil
	}
	// Reserve the global fd budget LAST — only now that per-VIP and per-source pass.
	// A failed reservation increments nothing; a successful one is immediately paired
	// with the insert below, so no release-on-reject path is ever reachable.
	if !r.budget.reserve() {
		r.mu.Unlock()
		_ = up.Close()
		if time.Since(*lastWarn) >= udpSaturationWarnInterval {
			*lastWarn = time.Now()
			r.log.Warn("udp relay global fd budget exhausted; dropping new flow", "vip", r.key.String(), "budget", r.budget.max)
		}
		return nil
	}
	fl := &udpFlow{upstream: up, clientAddr: clientAddr, srcIP: srcIP, lastActivity: time.Now()}
	r.flows[clientKey] = fl
	r.perSource[srcIP]++ // counted at insert only — mirrors the flows insert exactly
	r.wg.Add(1)
	go r.readUpstream(fl)
	r.mu.Unlock()
	return up
}

// srcIPOf extracts the source IP that keys clientAddr's per-source fair-share
// bucket. On a UDP PacketConn the address is always a *net.UDPAddr; the string-parse
// fallback covers any other net.Addr defensively. The address is Unmap'd so a
// 4-in-6 and a bare v4 form of the same source collapse to one bucket. A zero Addr
// (an unparseable address) is a single shared bucket — acceptable, since a UDP
// datagram always carries a concrete source.
func srcIPOf(clientAddr net.Addr) netip.Addr {
	if ua, ok := clientAddr.(*net.UDPAddr); ok {
		return ua.AddrPort().Addr().Unmap()
	}
	if ap, err := netip.ParseAddrPort(clientAddr.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// readUpstream relays one flow's backend responses to the client until the
// upstream socket is closed (sweeper idle-GC or Close) or the VIP socket is closed
// (Close). It writes each response with the VIP as the source (conn.WriteTo) so the
// client's connected socket accepts it.
func (r *udpRelay) readUpstream(fl *udpFlow) {
	defer r.wg.Done()
	buf := make([]byte, maxUDPDatagram)
	for {
		n, err := fl.upstream.Read(buf)
		if err != nil {
			return // upstream closed → flow ended
		}
		if _, err := r.conn.WriteTo(buf[:n], fl.clientAddr); err != nil {
			return // VIP socket closed → shutting down
		}
		r.mu.Lock()
		fl.lastActivity = time.Now()
		r.mu.Unlock()
	}
}

// sweep idle-GCs flows: every idleTimeout/2 it closes and removes flows silent for
// at least idleTimeout (closing the upstream socket unblocks that flow's reader,
// which then exits). It returns when done is closed (Close).
func (r *udpRelay) sweep() {
	defer r.wg.Done()
	interval := r.idleTimeout / 2
	if interval <= 0 {
		interval = r.idleTimeout
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.done:
			return
		case now := <-ticker.C:
			r.sweepExpired(now)
		}
	}
}

// sweepExpired closes and removes every flow idle for at least idleTimeout as of
// now, un-counting each reaped flow's per-source and global-budget slots
// symmetrically via releaseFlowLocked (the counters mirror flows membership — a flow
// counted at insert is un-counted here, at its delete). Closing the upstream socket
// unblocks that flow's reader, which then exits. It holds mu for the whole pass. It
// is factored out of sweep so a test can force a deterministic sweep.
func (r *udpRelay) sweepExpired(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, fl := range r.flows {
		if now.Sub(fl.lastActivity) >= r.idleTimeout {
			_ = fl.upstream.Close()
			delete(r.flows, k)
			r.releaseFlowLocked(fl)
		}
	}
}

// releaseFlowLocked un-counts one flow being removed from r.flows: it decrements the
// per-source count (pruning the entry at zero so an idle source leaks no map slot)
// and releases the flow's global fd-budget slot. It MUST be called exactly once per
// flow deleted from r.flows, and only while holding mu (it mutates perSource; the
// budget is a leaf, safe under mu). Pairing it 1:1 with a flow delete is what keeps
// both counters an exact function of flows membership.
func (r *udpRelay) releaseFlowLocked(fl *udpFlow) {
	r.perSource[fl.srcIP]--
	if r.perSource[fl.srcIP] <= 0 {
		delete(r.perSource, fl.srcIP)
	}
	r.budget.release()
}

// Close tears the relay down leak-free: it closes the VIP socket (unblocking the
// dispatcher's ReadFrom), stops the sweeper, closes every flow's upstream socket
// (unblocking each reader's Read), and joins the dispatcher, the sweeper, and all
// readers through wg before returning. It is idempotent. Setting closed under mu
// before the dispatcher can insert again guarantees no reader is spawned after the
// join begins. Draining the table un-counts every live flow via releaseFlowLocked,
// so this relay's contribution to the shared global budget returns to zero (no
// cross-relay fd leak) and the per-source map empties.
func (r *udpRelay) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	flows := r.flows
	// Un-count every live flow (per-source-- and budget.release()) under mu, atomically
	// with the drain, so the release count exactly matches the flows removed here.
	for _, fl := range flows {
		r.releaseFlowLocked(fl)
	}
	r.flows = make(map[string]*udpFlow)
	r.mu.Unlock()

	close(r.done)         // stop the sweeper
	err := r.conn.Close() // unblock the dispatcher's ReadFrom

	for _, fl := range flows {
		_ = fl.upstream.Close() // unblock each reader's Read
	}

	r.wg.Wait() // join dispatcher + sweeper + every reader
	return err
}
