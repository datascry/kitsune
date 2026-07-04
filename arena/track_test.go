// arena/track_test — the moving-target stale-snapshot probe: a click on the seconds-old issue position (after the
// target moved, past the age floor) is stale; a click on the current target, or a fast click, is not. FP-safe.

package arena

import (
	"testing"
	"time"
)

func TestTrackStaleSnapshot(t *testing.T) {
	s := newTrackStore()
	t0 := time.Now()
	seed := func() { s.m["tk"] = &trackTarget{x0: 100, y0: 100, vx: 60, vy: 0, issued: t0} } // +60 px/s in x

	// STALE: snapshot-then-slowly-reason agent clicks the ISSUE position (100,100) at t0+2s. The target is now at
	// (220,100) — the click is on a 2s-old view, far from current, past the 1.2s floor -> stale.
	seed()
	if hit, stale, ok := s.verify("tk", 100, 100, t0.Add(2*time.Second)); !ok || hit || !stale {
		t.Fatalf("stale click: hit=%v stale=%v ok=%v — want false/true/true", hit, stale, ok)
	}

	// MID-PATH STALE: the widget agent snapshots MID-FLIGHT (not at the start). At t0+3s it clicks (160,100), where
	// the dot was at dt=1s — a 2s-old view, far from current (280,100) -> stale wherever along the path it was seen.
	seed()
	if _, stale, _ := s.verify("tk", 160, 100, t0.Add(3*time.Second)); !stale {
		t.Fatal("a mid-path click on a >1.2s-old position must be stale")
	}

	// LIVE: a human re-perceives and clicks the CURRENT target (220,100) at t0+2s -> hit, not stale.
	seed()
	if hit, stale, _ := s.verify("tk", 220, 100, t0.Add(2*time.Second)); !hit || stale {
		t.Fatalf("live click: hit=%v stale=%v — want true/false", hit, stale)
	}

	// SLOW human who still clicks the CURRENT (clamped) target 5s later -> not stale (a human never acts on a stale view).
	seed()
	if _, stale, _ := s.verify("tk", 320, 100, t0.Add(5*time.Second)); stale {
		t.Fatal("a slow human clicking the CURRENT target must not be stale")
	}

	// FAST: clicking the issue position before the age floor is not stale (the floor tell would own a superhuman one).
	seed()
	if _, stale, _ := s.verify("tk", 100, 100, t0.Add(500*time.Millisecond)); stale {
		t.Fatal("a click below the age floor must not be stale")
	}

	// single-use + unknown ticket
	seed()
	_, _, _ = s.verify("tk", 100, 100, t0.Add(2*time.Second))
	if _, _, ok := s.verify("tk", 100, 100, t0.Add(2*time.Second)); ok {
		t.Fatal("track ticket was not single-use")
	}
	if _, _, ok := s.verify("never", 0, 0, t0); ok {
		t.Fatal("an unknown ticket must not verify")
	}

	// current() reports the live position and clamps to the canvas.
	seed()
	if x, _, ok := s.current("tk", t0.Add(1*time.Second)); !ok || x != 160 {
		t.Fatalf("current at t+1s: x=%v ok=%v — want 160/true", x, ok)
	}
}

func TestTrackIssueAndClamp(t *testing.T) {
	s := newTrackStore()
	x, y, _, _ := s.issue("id", time.Now(), 30, 40)
	if x < 0 || x > trackCanvas || y < 0 || y > trackCanvas {
		t.Fatalf("issue position off canvas: (%v,%v)", x, y)
	}
	if _, _, ok := s.current("id", time.Now().Add(time.Hour)); !ok { // far future -> clamped, still known
		t.Fatal("known ticket lost")
	}
}

func TestTrackSpeedForLevel(t *testing.T) {
	e, _ := trackSpeedForLevel(LevelEasy)
	m, _ := trackSpeedForLevel(LevelMedium)
	h, _ := trackSpeedForLevel(LevelHard)
	if !(e < m && m < h) {
		t.Fatalf("dot speed must rise with difficulty: easy=%d medium=%d hard=%d", e, m, h)
	}
}
