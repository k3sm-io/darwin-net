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
	"time"
)

// maxUDPFlows bounds the relay's per-VIP flow table. Same-node pods share one
// trust domain with no per-pod uid isolation, so a single pod cycling ephemeral
// source ports must not exhaust file descriptors and goroutines for every Service
// the proxy owns. On saturation a NEW flow is dropped (a live flow is never
// evicted); the cap is generous so legitimate fan-in is unaffected.
const maxUDPFlows = 8192

// maxUDPDatagram is the read buffer size for one datagram. A datagram socket
// discards any bytes beyond the supplied buffer, so it is sized to the maximum
// IPv4 UDP payload to avoid truncating a large datagram. One buffer is held per
// live flow reader, so worst-case buffer memory is bounded by maxUDPFlows.
const maxUDPDatagram = 65535

// udpSaturationWarnInterval throttles the flow-table-saturation Warn so a pod
// flooding new flows logs at most once per interval, not once per dropped
// datagram.
const udpSaturationWarnInterval = 10 * time.Second

// udpFlow is one client→backend datagram flow: a connected upstream socket to the
// backend picked once for this client 5-tuple, plus the client address responses
// are written back to. lastActivity drives idle GC.
//
// Locking discipline: lastActivity is guarded by udpRelay.mu — it is written by
// the dispatcher on a client→upstream datagram and by the reader on an
// upstream→client datagram, and read by the sweeper. upstream and clientAddr are
// set once before the reader goroutine is started and never mutated, so the reader
// reads them without the lock (the goroutine-start happens-before covers it).
type udpFlow struct {
	upstream     *net.UDPConn
	clientAddr   net.Addr
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
// constrain every cross-node source to the sending node's pod CIDR. The per-VIP cap
// (maxUDPFlows) bounds total flows but is not a per-source fair-share quota; a global
// fd budget and a per-source sub-cap are deferred to B48.
//
// Locking discipline: mu guards flows, closed, and each flow's lastActivity. The
// dispatcher is the SOLE inserter; the sweeper and Close are the only removers;
// readers only update lastActivity. Pick and all socket I/O run OUTSIDE mu (Pick
// has its own lock; a blocking Read/Write must never hold mu). Close joins the
// dispatcher, the sweeper, and every reader through wg before returning, so
// teardown strands no goroutine.
type udpRelay struct {
	conn        net.PacketConn
	key         PortKey
	table       *RoutingTable
	meshEgress  netip.Addr
	idleTimeout time.Duration
	log         *slog.Logger

	mu     sync.Mutex
	closed bool
	flows  map[string]*udpFlow

	done chan struct{}
	wg   sync.WaitGroup
}

// newUDPRelay builds a relay serving conn (the VIP datagram socket) for key,
// selecting backends from table. meshEgress, when valid, source-binds each
// per-flow upstream socket (the multi-node mesh path); the zero Addr keeps the
// kernel's default source selection (single node). idleTimeout is the flow GC
// idle timeout. Call start to run it and Close to tear it down.
func newUDPRelay(conn net.PacketConn, key PortKey, table *RoutingTable, meshEgress netip.Addr, idleTimeout time.Duration, log *slog.Logger) *udpRelay {
	return &udpRelay{
		conn:        conn,
		key:         key,
		table:       table,
		meshEgress:  meshEgress,
		idleTimeout: idleTimeout,
		log:         log,
		flows:       make(map[string]*udpFlow),
		done:        make(chan struct{}),
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
// datagram is dropped — when there is no Ready backend, the flow cap is reached (a
// throttled Warn via lastWarn), the dial fails, or the relay is closing. Pick and
// DialUDP run outside mu; only the map lookup and insert hold it. lastWarn is the
// dispatcher-local saturation-warn throttle (the dispatcher is the only caller).
func (r *udpRelay) upstreamFor(clientAddr net.Addr, lastWarn *time.Time) *net.UDPConn {
	clientKey := clientAddr.String()

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
	if len(r.flows) >= maxUDPFlows {
		r.mu.Unlock()
		if time.Since(*lastWarn) >= udpSaturationWarnInterval {
			*lastWarn = time.Now()
			r.log.Warn("udp relay flow table saturated; dropping new flow", "vip", r.key.String(), "maxFlows", maxUDPFlows)
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
		// just-dialed socket or spawn a reader that Close would never join.
		r.mu.Unlock()
		_ = up.Close()
		return nil
	}
	fl := &udpFlow{upstream: up, clientAddr: clientAddr, lastActivity: time.Now()}
	r.flows[clientKey] = fl
	r.wg.Add(1)
	go r.readUpstream(fl)
	r.mu.Unlock()
	return up
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
			r.mu.Lock()
			for k, fl := range r.flows {
				if now.Sub(fl.lastActivity) >= r.idleTimeout {
					_ = fl.upstream.Close()
					delete(r.flows, k)
				}
			}
			r.mu.Unlock()
		}
	}
}

// Close tears the relay down leak-free: it closes the VIP socket (unblocking the
// dispatcher's ReadFrom), stops the sweeper, closes every flow's upstream socket
// (unblocking each reader's Read), and joins the dispatcher, the sweeper, and all
// readers through wg before returning. It is idempotent. Setting closed under mu
// before the dispatcher can insert again guarantees no reader is spawned after the
// join begins.
func (r *udpRelay) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	flows := r.flows
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
