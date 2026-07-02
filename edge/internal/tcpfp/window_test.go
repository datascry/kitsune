// edge/tcpfp/window_test — the receive-window auto-tuning tracker.
// A static-window flow (userspace stack) flags; an auto-tuning (growing-window) flow does not.

package tcpfp

import (
	"testing"
	"time"
)

func TestWindowTrackerStatic(t *testing.T) {
	w := NewWindowTracker(time.Minute)
	// A userspace stack: 15 segments, all the same window -> static once past the floor.
	for i := 0; i < 15; i++ {
		w.Observe("10.0.0.1", 64240)
	}
	if !w.Static("10.0.0.1", 12) {
		t.Error("a flow of 15 identical windows must be flagged static")
	}
	// A real kernel: window grows across the flow -> never static.
	for i := 0; i < 15; i++ {
		w.Observe("10.0.0.2", uint16(600+i*100))
	}
	if w.Static("10.0.0.2", 12) {
		t.Error("an auto-tuned (growing) window must not be flagged static")
	}
	// Below the segment floor: too little evidence.
	for i := 0; i < 5; i++ {
		w.Observe("10.0.0.3", 65535)
	}
	if w.Static("10.0.0.3", 12) {
		t.Error("a short flow (< floor) must not be flagged static")
	}
	if w.Static("10.0.0.9", 12) {
		t.Error("an unseen IP must not be flagged")
	}
}
