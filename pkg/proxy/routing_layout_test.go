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
	"testing"
	"unsafe"
)

// TestPortStateCursorIsolatedCacheLine pins the portState memory layout that
// keeps the two per-pick-written atomics (cursor, warned) off the cache line
// holding the per-pick-read fields (all, locals, policy, affinity config, the
// membership sets). Without the padding, every pick's fetch-add on cursor
// invalidates the line every other pick is reading its pool selection from, so
// N cores sharing one key ping-pong a line that is logically read-mostly.
//
// This test is the alarm on that layout: reordering, adding, or resizing any
// read-only field shifts the offsets and fails here, which is the signal to
// recompute the leading pad in routing.go — the padding is arithmetic over the
// field sizes, and nothing else checks it.
func TestPortStateCursorIsolatedCacheLine(t *testing.T) {
	var st portState

	cursorOff := unsafe.Offsetof(st.cursor)
	warnedOff := unsafe.Offsetof(st.warned)
	cursorLine := cursorOff / cacheLineSize

	t.Run("cursor starts a cache line", func(t *testing.T) {
		if cursorOff%cacheLineSize != 0 {
			t.Errorf("cursor is at offset %d, which is not a multiple of the %d-byte cache line "+
				"(line %d, %d bytes in): recompute the leading pad in portState",
				cursorOff, uintptr(cacheLineSize), cursorLine, cursorOff%cacheLineSize)
		}
	})

	t.Run("warned shares the cursor line", func(t *testing.T) {
		// The two atomics are written by the same pick, so they belong together:
		// splitting them would dirty two lines per pick instead of one.
		if got := warnedOff / cacheLineSize; got != cursorLine {
			t.Errorf("warned is at offset %d (line %d), cursor at offset %d (line %d): "+
				"the two per-pick writes must share one line",
				warnedOff, got, cursorOff, cursorLine)
		}
		if end := warnedOff + unsafe.Sizeof(st.warned); (end-1)/cacheLineSize != cursorLine {
			t.Errorf("warned spans offsets [%d,%d) and runs past the end of line %d: "+
				"the atomic must fit inside the cursor's line", warnedOff, end, cursorLine)
		}
	})

	t.Run("no read-only field shares the cursor line", func(t *testing.T) {
		// Every field a pick reads but never writes. Enumerated by hand on purpose:
		// a new field added to portState is not covered until it is listed here.
		readOnly := []struct {
			name string
			off  uintptr
			size uintptr
		}{
			{"all", unsafe.Offsetof(st.all), unsafe.Sizeof(st.all)},
			{"locals", unsafe.Offsetof(st.locals), unsafe.Sizeof(st.locals)},
			{"policy", unsafe.Offsetof(st.policy), unsafe.Sizeof(st.policy)},
			{"affinityMode", unsafe.Offsetof(st.affinityMode), unsafe.Sizeof(st.affinityMode)},
			{"affinityTimeout", unsafe.Offsetof(st.affinityTimeout), unsafe.Sizeof(st.affinityTimeout)},
			{"allSet", unsafe.Offsetof(st.allSet), unsafe.Sizeof(st.allSet)},
			{"localSet", unsafe.Offsetof(st.localSet), unsafe.Sizeof(st.localSet)},
		}
		for _, f := range readOnly {
			for _, line := range [2]uintptr{f.off / cacheLineSize, (f.off + f.size - 1) / cacheLineSize} {
				if line == cursorLine {
					t.Errorf("%s spans offsets [%d,%d) and touches line %d, which holds cursor "+
						"(offset %d): a per-pick write would invalidate a per-pick read",
						f.name, f.off, f.off+f.size, cursorLine, cursorOff)
					break
				}
			}
		}
	})

	t.Run("the struct is a whole number of cache lines", func(t *testing.T) {
		// Without a trailing pad the allocator can place the next heap object's
		// header on the cursor's line, reintroducing the sharing across keys.
		if size := unsafe.Sizeof(st); size%cacheLineSize != 0 {
			t.Errorf("portState is %d bytes, not a multiple of the %d-byte cache line "+
				"(%d bytes into the last line): recompute the trailing pad",
				size, uintptr(cacheLineSize), size%cacheLineSize)
		}
	})
}
