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

// Package linkwatch reports network-interface link changes: an interface coming
// up, going down, or vanishing. It is how the mesh learns that a direct-link
// cable was plugged or pulled without waiting for its periodic resync.
//
// Two sources feed one stream. The PRIMARY, and the only mandatory one, is a
// poll every 2 s (Poller) of net.Interfaces() flags plus each up interface's
// carrier, read with SIOCGIFMEDIA: pure Go, unprivileged, and independent of any
// kernel notification path. The poll is the source that sees a cable pull: a
// pulled Thunderbolt cable leaves the interface IFF_UP and IFF_RUNNING and in
// the interface list, and changes only its media status (ifconfig's
// "status: inactive"), which only the carrier read observes. The OPTIMISATION is
// a read-only PF_ROUTE socket (RouteReader) that sees RTM_IFINFO, RTM_NEWADDR
// and RTM_DELADDR as they happen; reading the routing socket needs no privilege,
// only writing to it does. It reports administrative changes (ifconfig up/down,
// addresses, an interface appearing or vanishing), not a carrier loss, and is
// opened best-effort: when it cannot be opened the poll alone carries the
// stream. Both are merged and debounced (500 ms, trailing), and an event equal
// to the last one delivered for that interface is dropped, so a change both
// sources see is delivered once.
//
// Consumers depend on LinkEvents and nothing else; Watch builds the production
// stream.
package linkwatch

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"time"
)

const (
	// PollInterval is the flag-poll period.
	PollInterval = 2 * time.Second
	// DebounceWindow is the quiet period a burst of events waits out before it
	// is delivered.
	DebounceWindow = 500 * time.Millisecond
	// eventBuffer is the capacity of every stream channel this package creates.
	eventBuffer = 64
)

// Event is one interface's link state after a change.
type Event struct {
	// Iface is the interface name (e.g. "en2").
	Iface string
	// Up reports that the interface is administratively up AND running AND,
	// where the driver reports it, has an active carrier. It is false whenever
	// Gone is true.
	Up bool
	// Gone reports that the interface no longer exists. A consumer treats a
	// vanished interface as a removal, not as a flag flip.
	Gone bool
}

// LinkEvents is a stream of link events. The channel is closed after ctx is
// cancelled.
type LinkEvents interface {
	Events(ctx context.Context) <-chan Event
}

// Clock is the time seam the poll and the debounce run on.
type Clock interface {
	// Ticker returns a channel ticking every d and a function that stops it.
	Ticker(d time.Duration) (<-chan time.Time, func())
	// After returns a channel that receives once, after d.
	After(d time.Duration) <-chan time.Time
}

// RealClock is the production Clock.
type RealClock struct{}

// Ticker implements Clock with a time.Ticker.
func (RealClock) Ticker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// After implements Clock with time.After.
func (RealClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Watch returns the production stream: the 2 s flag poll merged with a
// best-effort PF_ROUTE reader, debounced. A reader that cannot be opened is
// logged at Info and the poll runs alone.
func Watch(log *slog.Logger) LinkEvents {
	if log == nil {
		log = slog.Default()
	}
	return watch{log: log}
}

type watch struct{ log *slog.Logger }

func (w watch) Events(ctx context.Context) <-chan Event {
	sources := []LinkEvents{Poller{}}
	if rr, err := OpenRouteReader(); err != nil {
		w.log.Info("link watch: PF_ROUTE reader unavailable, the 2 s poll is the only source", "err", err)
	} else {
		sources = append(sources, rr)
	}
	return Debounce(ctx, Merge(ctx, sources...), DebounceWindow, RealClock{})
}

// Poller is the mandatory poll source. Its first pass reports every interface's
// state; later passes report only changes and vanishings. An interface is up
// when its flags say up and running and its carrier is not known to be lost. The
// zero value polls net.Interfaces and SIOCGIFMEDIA every PollInterval on the
// real clock.
type Poller struct {
	// Interval is the poll period; 0 uses PollInterval.
	Interval time.Duration
	// List lists the interfaces; nil uses net.Interfaces.
	List func() ([]net.Interface, error)
	// Carrier reads one interface's carrier: up is meaningful only when known
	// is true, and known false means the driver does not report it. nil uses
	// MediaCarrier.
	Carrier func(iface string) (up, known bool, err error)
	// Clock drives the ticker; nil uses RealClock.
	Clock Clock
	// Log receives list failures (Debug) and the first carrier-read failure
	// per interface (Info); nil uses slog.Default.
	Log *slog.Logger
}

// Events implements LinkEvents.
func (p Poller) Events(ctx context.Context) <-chan Event {
	interval := p.Interval
	if interval <= 0 {
		interval = PollInterval
	}
	list := p.List
	if list == nil {
		list = net.Interfaces
	}
	carrier := p.Carrier
	if carrier == nil {
		carrier = MediaCarrier
	}
	clock := p.Clock
	if clock == nil {
		clock = RealClock{}
	}
	log := p.Log
	if log == nil {
		log = slog.Default()
	}
	out := make(chan Event, eventBuffer)
	go func() {
		defer close(out)
		ticks, stop := clock.Ticker(interval)
		defer stop()
		var last map[string]bool             // nil until the first successful list
		mediaLogged := make(map[string]bool) // interfaces whose carrier error was logged
		for {
			ifaces, err := list()
			if err != nil {
				log.Debug("link watch: listing interfaces", "err", err)
			} else {
				next := make(map[string]bool, len(ifaces))
				for _, ifi := range ifaces {
					up := linkUp(ifi.Flags)
					if up {
						cup, known, err := carrier(ifi.Name)
						switch {
						case err != nil:
							// Unknown: the flags decide, and the other
							// interfaces are unaffected.
							if !mediaLogged[ifi.Name] {
								mediaLogged[ifi.Name] = true
								log.Info("link watch: reading carrier, using the interface flags alone", "iface", ifi.Name, "err", err)
							}
						case known:
							up = cup
						}
					}
					next[ifi.Name] = up
				}
				for _, ev := range diff(last, next) {
					select {
					case out <- ev:
					case <-ctx.Done():
						return
					}
				}
				last = next
			}
			select {
			case <-ctx.Done():
				return
			case <-ticks:
			}
		}
	}()
	return out
}

// linkUp reports whether flags describe an interface that is up and has link.
func linkUp(f net.Flags) bool { return f&net.FlagUp != 0 && f&net.FlagRunning != 0 }

// diff returns the events that move a consumer from prev to next, sorted by
// interface name: every interface on the first pass (prev nil), else a change of
// state or a vanishing.
func diff(prev, next map[string]bool) []Event {
	var out []Event
	for name, up := range next {
		if was, ok := prev[name]; prev == nil || !ok || was != up {
			out = append(out, Event{Iface: name, Up: up})
		}
	}
	for name := range prev {
		if _, ok := next[name]; !ok {
			out = append(out, Event{Iface: name, Gone: true})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Iface < out[j].Iface })
	return out
}

// Merge fans several streams into one, closed once every input has closed.
func Merge(ctx context.Context, sources ...LinkEvents) <-chan Event {
	out := make(chan Event, eventBuffer)
	done := make(chan struct{})
	for _, s := range sources {
		in := s.Events(ctx)
		go func() {
			defer func() { done <- struct{}{} }()
			for ev := range in {
				select {
				case out <- ev:
				case <-ctx.Done():
					// Drain so the source's sender is not blocked; it closes
					// its channel once it sees ctx.
					for range in {
					}
					return
				}
			}
		}()
	}
	go func() {
		for range sources {
			<-done
		}
		close(out)
	}()
	return out
}

// Debounce delivers in's events after a quiet period of window: every event
// restarts the wait, and when it expires the latest state of each interface in
// the burst is delivered (sorted by name), minus any equal to the last state
// delivered for that interface. The output closes when in closes or ctx ends.
func Debounce(ctx context.Context, in <-chan Event, window time.Duration, clock Clock) <-chan Event {
	out := make(chan Event, eventBuffer)
	go func() {
		defer close(out)
		pending := make(map[string]Event)
		delivered := make(map[string]Event)
		var timer <-chan time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-in:
				if !ok {
					return
				}
				pending[ev.Iface] = ev
				timer = clock.After(window)
			case <-timer:
				timer = nil
				names := make([]string, 0, len(pending))
				for name := range pending {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					ev := pending[name]
					delete(pending, name)
					if last, ok := delivered[name]; ok && last == ev {
						continue
					}
					delivered[name] = ev
					select {
					case out <- ev:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	return out
}
