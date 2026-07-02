// edge/tcpfp/window — per-source-IP TCP receive-window tracker for detecting a non-auto-tuning stack.
// A real kernel grows its advertised window across a flow; a hand-rolled/userspace stack holds it constant.

package tcpfp

import (
	"sync"
	"time"
)

type winEntry struct {
	values map[uint16]struct{} // distinct advertised windows seen (capped)
	count  int                 // non-SYN client segments observed
	at     time.Time
}

// WindowTracker records the distinct TCP receive-window values a source IP advertises on its established
// (non-SYN) segments. A real OS auto-tunes the window (many distinct values across a flow); a happy-path
// userspace stack advertises a single constant window — so a flow with many segments but ONE window value is
// a non-auto-tuning stack. Single-writer feed from the sniffer goroutine; reads take the lock.
type WindowTracker struct {
	mu    sync.Mutex
	m     map[string]*winEntry
	ttl   time.Duration
	now   func() time.Time
	sweep time.Time
}

// NewWindowTracker returns a tracker whose per-IP entries live for ttl.
func NewWindowTracker(ttl time.Duration) *WindowTracker {
	return &WindowTracker{m: map[string]*winEntry{}, ttl: ttl, now: time.Now}
}

const _maxWindowValues = 16 // cap the per-IP set; once past 1 it is already "not static", so no need to grow

// Observe records one non-SYN segment's advertised window for ip.
func (w *WindowTracker) Observe(ip string, window uint16) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	e := w.m[ip]
	if e == nil {
		e = &winEntry{values: map[uint16]struct{}{}}
		w.m[ip] = e
	}
	e.count++
	e.at = now
	if len(e.values) < _maxWindowValues {
		e.values[window] = struct{}{}
	}
	if now.Sub(w.sweep) > w.ttl { // amortised eviction (mirrors the SYN Store)
		for k, v := range w.m {
			if now.Sub(v.at) > w.ttl {
				delete(w.m, k)
			}
		}
		w.sweep = now
	}
}

// Static reports whether ip has sent at least minSegments established segments that ALL advertised the same
// window — a stack that never auto-tuned. Below minSegments it returns false (too little evidence: a real
// short flow may legitimately not have grown its window yet).
func (w *WindowTracker) Static(ip string, minSegments int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	e := w.m[ip]
	if e == nil || w.now().Sub(e.at) > w.ttl {
		return false
	}
	return e.count >= minSegments && len(e.values) == 1
}
