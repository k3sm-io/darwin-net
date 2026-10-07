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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	// ProbeInterval is how often each direct peer is probed.
	ProbeInterval = 5 * time.Second
	// ProbeMisses is how many consecutive unanswered probes declare a direct
	// peer dead (15 s at ProbeInterval).
	ProbeMisses = 3
	// probeTimeout bounds one echo's wait for its reply.
	probeTimeout = 2 * time.Second
)

// ProbeTarget is one direct peer to probe: the local cable interface and the
// peer's link address on it.
type ProbeTarget struct {
	Iface string
	Peer  netip.Addr
}

// pinger sends one ICMP echo and waits for its reply. It is the probe's I/O seam.
type pinger interface {
	Ping(ctx context.Context, dst netip.Addr, timeout time.Duration) error
}

// Prober is the direct-link liveness probe. A cable whose peer sleeps or hangs
// raises no link event (Thunderbolt has no wake-on-LAN, and the local link stays
// up), so liveness is probed, not inferred: every ProbeInterval each target gets
// one ICMP echo; a target is alive from its first answered echo and dead after
// ProbeMisses unanswered ones in a row, and it comes back only when an echo is
// answered again. Every transition calls the onChange callback (outside any lock).
//
// A new target starts dead: the cable carries pods only after the peer has
// answered over it.
//
// Locking discipline: mu guards targets and state; Ping runs without it, so a slow
// echo never blocks Alive.
type Prober struct {
	ping     pinger
	onChange func(t ProbeTarget, alive bool)

	mu      sync.Mutex
	targets map[ProbeTarget]*probeState
}

type probeState struct {
	alive  bool
	misses int
}

// newProber returns a Prober using p (nil: the unprivileged ICMP pinger).
func newProber(p pinger, onChange func(ProbeTarget, bool)) *Prober {
	if p == nil {
		p = icmpPinger{}
	}
	return &Prober{ping: p, onChange: onChange, targets: make(map[ProbeTarget]*probeState)}
}

// SetTargets replaces the probed set. A target that stays keeps its state; a new
// one starts dead; a removed one is forgotten.
func (p *Prober) SetTargets(targets []ProbeTarget) {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := make(map[ProbeTarget]*probeState, len(targets))
	for _, t := range targets {
		if st, ok := p.targets[t]; ok {
			next[t] = st
			continue
		}
		next[t] = &probeState{}
	}
	p.targets = next
}

// Alive reports whether the peer at peer on iface currently answers.
func (p *Prober) Alive(iface string, peer netip.Addr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.targets[ProbeTarget{Iface: iface, Peer: peer}]
	return ok && st.alive
}

// Run probes every target once per ProbeInterval until ctx ends.
func (p *Prober) Run(ctx context.Context) {
	t := time.NewTicker(ProbeInterval)
	defer t.Stop()
	for {
		p.round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// round sends one echo to every target concurrently, folds the results into the
// state, and reports the transitions.
func (p *Prober) round(ctx context.Context) {
	p.mu.Lock()
	targets := make([]ProbeTarget, 0, len(p.targets))
	for t := range p.targets {
		targets = append(targets, t)
	}
	p.mu.Unlock()

	results := make([]error, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = p.ping.Ping(ctx, t.Peer, probeTimeout)
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}

	type change struct {
		t     ProbeTarget
		alive bool
	}
	var changes []change
	p.mu.Lock()
	for i, t := range targets {
		st, ok := p.targets[t]
		if !ok {
			continue // removed while the echo was in flight
		}
		if results[i] == nil {
			st.misses = 0
			if !st.alive {
				st.alive = true
				changes = append(changes, change{t, true})
			}
			continue
		}
		st.misses++
		if st.alive && st.misses >= ProbeMisses {
			st.alive = false
			changes = append(changes, change{t, false})
		}
	}
	p.mu.Unlock()
	for _, c := range changes {
		if p.onChange != nil {
			p.onChange(c.t, c.alive)
		}
	}
}

// icmpPinger is the production pinger: an unprivileged ICMP datagram socket
// (SOCK_DGRAM, IPPROTO_ICMP — "udp4" in golang.org/x/net/icmp), which macOS opens
// for any user, so the probe runs as the service user with no raw socket and no
// ping(8) exec. One socket per echo keeps the code free of a demultiplexer; at one
// echo per peer per 5 s the cost is nothing.
type icmpPinger struct{}

// Ping sends one echo to dst and waits up to timeout for the matching reply.
func (icmpPinger) Ping(ctx context.Context, dst netip.Addr, timeout time.Duration) error {
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("open icmp socket: %w", err)
	}
	defer c.Close()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := c.SetDeadline(deadline); err != nil {
		return fmt.Errorf("arm icmp deadline: %w", err)
	}
	id := os.Getpid() & 0xffff
	seq := int(time.Now().UnixNano() & 0xffff)
	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("k3sm-direct-link")}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("marshal icmp echo: %w", err)
	}
	to := &net.UDPAddr{IP: net.IP(dst.AsSlice())}
	if _, err := c.WriteTo(b, to); err != nil {
		return fmt.Errorf("send icmp echo to %s: %w", dst, err)
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("await icmp echo reply from %s: %w", dst, err)
		}
		if ua, ok := from.(*net.UDPAddr); !ok || !ua.IP.Equal(to.IP) {
			continue
		}
		rm, err := icmp.ParseMessage(1, buf[:n]) // 1 = IPPROTO_ICMP
		if err != nil || rm.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		// The kernel owns the identifier on a datagram ICMP socket, so only the
		// sequence is matched.
		if echo, ok := rm.Body.(*icmp.Echo); ok && echo.Seq == seq {
			return nil
		}
		if ctx.Err() != nil {
			return errors.Join(ctx.Err(), fmt.Errorf("await icmp echo reply from %s", dst))
		}
	}
}
