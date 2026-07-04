// arena/track — the moving-target gate: an LLM-agent STALE-SNAPSHOT probe (owned infra only).
// A target moves over time; a live client acts on its CURRENT position, a snapshot-then-slowly-reason agent
// acts on the STALE (issue-time) position it saw seconds ago — the one signal that survives a coherent fingerprint.

package arena

import (
	"math"
	"sync"
	"time"
)

// trackTarget is one client's moving target: it starts at (x0,y0) and moves at (vx,vy) px/s within a WxH canvas,
// clamped at the edges. The SERVER seeds the motion and records issuedAt, so the target's position at any instant
// is server-known and unforgeable — the client cannot backdate when it observed the target.
type trackTarget struct {
	x0, y0 float64
	vx, vy float64
	issued time.Time
}

const (
	trackCanvas    = 320.0                   // WxH canvas the target moves within
	trackTolerance = 28.0                    // a click within this of a position "hit" it (generous — human aim varies)
	trackStaleAge  = 1200 * time.Millisecond // a click on a position the target left more than this ago is STALE:
	//                                          no human acts on a >1.2s-old view (they re-perceive), only a
	//                                          snapshot-then-slowly-reason agent does. FP-safe LOWER bound.
)

// pos returns the target's position at time now (linear motion, clamped to the canvas).
func (t *trackTarget) pos(now time.Time) (float64, float64) {
	dt := now.Sub(t.issued).Seconds()
	return clampf(t.x0+t.vx*dt, 0, trackCanvas), clampf(t.y0+t.vy*dt, 0, trackCanvas)
}

func clampf(v, lo, hi float64) float64 {
	return math.Max(lo, math.Min(hi, v))
}

// trackStore issues single-use moving-target challenges.
type trackStore struct {
	mu sync.Mutex
	m  map[string]*trackTarget
}

func newTrackStore() *trackStore { return &trackStore{m: map[string]*trackTarget{}} }

// issue seeds a moving target and returns its id + START position (the "snapshot" a client sees at issue time).
func (s *trackStore) issue(id string, now time.Time) (float64, float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// start in the interior; velocity biased so the target clearly leaves its start within ~1-2s
	x0 := 60 + float64(randInt(80))
	y0 := 60 + float64(randInt(80))
	vx := 60 + float64(randInt(60))
	vy := 60 + float64(randInt(60))
	if randInt(2) == 0 {
		vx = -vx
	}
	if randInt(2) == 0 {
		vy = -vy
	}
	s.m[id] = &trackTarget{x0: x0, y0: y0, vx: vx, vy: vy, issued: now}
	return x0, y0
}

// current reports the target's position now, for a client that re-perceives before acting (a human tracking it).
func (s *trackStore) current(id string, now time.Time) (float64, float64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.m[id]
	if !ok {
		return 0, 0, false
	}
	x, y := t.pos(now)
	return x, y, true
}

// verify consumes the challenge and classifies a click at (cx,cy) observed at now. It returns whether the click
// hit the CURRENT target and whether it is a STALE-snapshot click (near where the target was >trackStaleAge ago
// AND far from where it is now — the LLM-agent signature). A human tracking the target clicks current -> not stale.
func (s *trackStore) verify(id string, cx, cy float64, now time.Time) (hit, stale, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, present := s.m[id]
	if !present {
		return false, false, false
	}
	delete(s.m, id) // single-use
	curX, curY := t.pos(now)
	hit = math.Hypot(cx-curX, cy-curY) <= trackTolerance
	// STALE-SNAPSHOT: the click is near the ISSUE-TIME position (the target where a step-start snapshot saw it),
	// the target has since MOVED away (the click is not on the current target), AND more than trackStaleAge has
	// elapsed since issue — i.e. the client acted on a >1.2s-old view. A human re-perceives and clicks the current
	// target; a fast script clicks before the target moves (age below the floor); only a snapshot-then-slowly-reason
	// agent clicks the old position this late.
	nearIssue := math.Hypot(cx-t.x0, cy-t.y0) <= trackTolerance
	stale = nearIssue && !hit && now.Sub(t.issued) > trackStaleAge
	return hit, stale, true
}
