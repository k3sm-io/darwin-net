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

package linkwatch

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeClock hands out channels the test fires by hand: one ticker channel and
// one channel per After call.
type fakeClock struct {
	mu     sync.Mutex
	tick   chan time.Time
	afters []chan time.Time
	asked  chan time.Duration // every After(d) is reported here
}

func newFakeClock() *fakeClock {
	return &fakeClock{tick: make(chan time.Time), asked: make(chan time.Duration, 64)}
}

func (c *fakeClock) Ticker(time.Duration) (<-chan time.Time, func()) { return c.tick, func() {} }

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.mu.Lock()
	c.afters = append(c.afters, ch)
	c.mu.Unlock()
	c.asked <- d
	return ch
}

// fireLatest fires the most recent After channel: the only one a trailing
// debounce still listens on.
func (c *fakeClock) fireLatest() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.afters[len(c.afters)-1] <- time.Time{}
}

// fakeLister serves a scripted sequence of interface lists, one per poll; the
// last is repeated.
type fakeLister struct {
	mu    sync.Mutex
	lists [][]net.Interface
	err   error
}

func (l *fakeLister) list() ([]net.Interface, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return nil, l.err
	}
	cur := l.lists[0]
	if len(l.lists) > 1 {
		l.lists = l.lists[1:]
	}
	return cur, nil
}

func iface(name string, up bool) net.Interface {
	f := net.Flags(0)
	if up {
		f = net.FlagUp | net.FlagRunning
	}
	return net.Interface{Name: name, Flags: f}
}

func recv(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("stream closed")
		}
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
	}
	return Event{}
}

func noEvent(t *testing.T, ch <-chan Event) {
	t.Helper()
	select {
	case ev := <-ch:
		t.Fatalf("unexpected event %+v", ev)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestPollerReportsStateChangesAndVanishings drives the mandatory poll over a
// fake lister: the first pass reports every interface, later passes only changes,
// a vanished interface is Gone (never a flag flip), and an administratively-up
// interface without link is down.
func TestPollerReportsStateChangesAndVanishings(t *testing.T) {
	clock := newFakeClock()
	lister := &fakeLister{lists: [][]net.Interface{
		{iface("en0", true), iface("en2", false)},
		{iface("en0", true), iface("en2", true)},
		{iface("en0", true), {Name: "en2", Flags: net.FlagUp}},
		{iface("en0", true)},
		{iface("en0", true), iface("en2", true)},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := Poller{List: lister.list, Clock: clock}.Events(ctx)

	if got := []Event{recv(t, ch), recv(t, ch)}; !reflect.DeepEqual(got, []Event{{Iface: "en0", Up: true}, {Iface: "en2"}}) {
		t.Fatalf("first pass = %+v", got)
	}
	steps := []Event{
		{Iface: "en2", Up: true}, // cable in
		{Iface: "en2"},           // up but no link
		{Iface: "en2", Gone: true},
		{Iface: "en2", Up: true}, // reappears
	}
	for _, want := range steps {
		clock.tick <- time.Time{}
		if got := recv(t, ch); got != want {
			t.Fatalf("event = %+v, want %+v", got, want)
		}
	}
	clock.tick <- time.Time{}
	noEvent(t, ch)
	cancel()
	for range ch {
	}
}

// TestPollerSurvivesAListFailure pins that a failing net.Interfaces is skipped,
// not fatal: the stream stays open and reports once listing works again.
func TestPollerSurvivesAListFailure(t *testing.T) {
	clock := newFakeClock()
	lister := &fakeLister{err: errors.New("boom")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := Poller{List: lister.list, Clock: clock}.Events(ctx)
	noEvent(t, ch)
	lister.mu.Lock()
	lister.err = nil
	lister.lists = [][]net.Interface{{iface("en3", true)}}
	lister.mu.Unlock()
	clock.tick <- time.Time{}
	if got := recv(t, ch); got != (Event{Iface: "en3", Up: true}) {
		t.Fatalf("event = %+v", got)
	}
}

// TestDebounceCoalescesABurstAndDropsRepeats pins the 500 ms trailing debounce:
// a flap inside the window is delivered as its final state only, the wait is the
// configured window, and a state equal to the last one delivered is dropped (two
// sources reporting one change).
func TestDebounceCoalescesABurstAndDropsRepeats(t *testing.T) {
	clock := newFakeClock()
	in := make(chan Event)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := Debounce(ctx, in, DebounceWindow, clock)

	in <- Event{Iface: "en2", Up: true}
	if d := <-clock.asked; d != 500*time.Millisecond {
		t.Fatalf("debounce window = %v, want 500ms", d)
	}
	in <- Event{Iface: "en2"}
	<-clock.asked
	in <- Event{Iface: "en2", Up: true}
	<-clock.asked
	in <- Event{Iface: "en3", Gone: true}
	<-clock.asked
	noEvent(t, out)
	clock.fireLatest()
	if got := []Event{recv(t, out), recv(t, out)}; !reflect.DeepEqual(got, []Event{{Iface: "en2", Up: true}, {Iface: "en3", Gone: true}}) {
		t.Fatalf("burst delivered %+v", got)
	}

	in <- Event{Iface: "en2", Up: true} // the second source's copy of the same change
	<-clock.asked
	clock.fireLatest()
	noEvent(t, out)

	in <- Event{Iface: "en2"}
	<-clock.asked
	clock.fireLatest()
	if got := recv(t, out); got != (Event{Iface: "en2"}) {
		t.Fatalf("event = %+v", got)
	}
	close(in)
	for range out {
	}
}

// chanSource is a LinkEvents over a test-fed channel.
type chanSource chan Event

func (c chanSource) Events(context.Context) <-chan Event { return c }

// TestMergeCombinesSourcesAndClosesAfterAll pins the combinator: events from
// either source arrive, and the merged stream closes only after both have.
func TestMergeCombinesSourcesAndClosesAfterAll(t *testing.T) {
	a, b := make(chanSource), make(chanSource)
	out := Merge(context.Background(), a, b)
	a <- Event{Iface: "en2", Up: true}
	b <- Event{Iface: "en3"}
	got := map[Event]bool{recv(t, out): true, recv(t, out): true}
	if !got[Event{Iface: "en2", Up: true}] || !got[Event{Iface: "en3"}] {
		t.Fatalf("merged %v", got)
	}
	close(a)
	noEvent(t, out)
	close(b)
	select {
	case _, ok := <-out:
		if ok {
			t.Fatal("event after both sources closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("merged stream did not close")
	}
}

// routeMsgBytes builds the shared if_msghdr / ifa_msghdr prefix a routing socket
// delivers.
func routeMsgBytes(typ int, flags int32, index int) []byte {
	b := make([]byte, 112)
	binary.NativeEndian.PutUint16(b[0:2], uint16(len(b)))
	b[2] = unix.RTM_VERSION
	b[3] = byte(typ)
	binary.NativeEndian.PutUint32(b[8:12], uint32(flags))
	binary.NativeEndian.PutUint16(b[12:14], uint16(index))
	return b
}

// TestRouteReaderDecodesLinkMessages pins the PF_ROUTE decode: RTM_IFINFO reads
// the flags it carries, an address change re-reads the interface, a vanished
// index is Gone under its last known name, and unrelated messages are ignored.
func TestRouteReaderDecodesLinkMessages(t *testing.T) {
	ifaces := map[int]*net.Interface{7: {Index: 7, Name: "en2", Flags: net.FlagUp | net.FlagRunning}}
	r := &RouteReader{names: make(map[int]string), lookup: func(i int) (*net.Interface, error) {
		if ifi, ok := ifaces[i]; ok {
			return ifi, nil
		}
		return nil, errors.New("no such interface")
	}}
	var buf []byte
	buf = append(buf, routeMsgBytes(unix.RTM_IFINFO, unix.IFF_UP, 7)...)                  // up, no link
	buf = append(buf, routeMsgBytes(unix.RTM_IFINFO, unix.IFF_UP|unix.IFF_RUNNING, 7)...) // link
	buf = append(buf, routeMsgBytes(unix.RTM_ADD, 0, 7)...)                               // a route: ignored
	buf = append(buf, routeMsgBytes(unix.RTM_NEWADDR, 0, 7)...)                           // re-read
	got := r.decode(buf)
	want := []Event{{Iface: "en2"}, {Iface: "en2", Up: true}, {Iface: "en2", Up: true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decode = %+v, want %+v", got, want)
	}

	delete(ifaces, 7)
	if got := r.decode(routeMsgBytes(unix.RTM_IFINFO, 0, 7)); !reflect.DeepEqual(got, []Event{{Iface: "en2", Gone: true}}) {
		t.Fatalf("vanished = %+v", got)
	}
	if got := r.decode(routeMsgBytes(unix.RTM_DELADDR, 0, 9)); len(got) != 0 {
		t.Fatalf("an index never named must be skipped, got %+v", got)
	}
	if got := r.decode([]byte{3, 0, 5}); len(got) != 0 {
		t.Fatalf("a truncated message must be skipped, got %+v", got)
	}
}
