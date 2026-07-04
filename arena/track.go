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
	trackTolerance = 40.0                    // a click within this of a position "hit" it (generous — a laggy, noisy
	//                                          human aim must reliably land; grounded against a realistic tracker)
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

// issue seeds a moving target and returns its START position + velocity (the client animates the dot from these;
// the START position is also the "snapshot" a step-start snapshot sees at issue time).
func (s *trackStore) issue(id string, now time.Time) (x0, y0, vx, vy float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// start in the interior; moderate speed (~30-70 px/s per axis) — fast enough to strand a snapshot-then-reason
	// agent, slow enough that a laggy human reliably tracks and clicks the dot (grounded human-solvability)
	x0 = 60 + float64(randInt(80))
	y0 = 60 + float64(randInt(80))
	vx = 30 + float64(randInt(40))
	vy = 30 + float64(randInt(40))
	if randInt(2) == 0 {
		vx = -vx
	}
	if randInt(2) == 0 {
		vy = -vy
	}
	s.m[id] = &trackTarget{x0: x0, y0: y0, vx: vx, vy: vy, issued: now}
	return x0, y0, vx, vy
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
	// STALE-SNAPSHOT: the click landed on a position the target occupied more than trackStaleAge ago and has since
	// left (it is not on the current target). A human re-perceives and clicks where the dot IS; a fast script clicks
	// before the target moves; only a snapshot-then-slowly-reason agent clicks a seconds-old view this late.
	stale = !hit && t.staleClick(cx, cy, now)
	return hit, stale, true
}

// staleClick reports whether (cx,cy) lies on the target's PAST path at a time more than trackStaleAge ago — the
// signature of acting on a seconds-old snapshot, wherever along the flight the snapshot was taken. It projects the
// click onto the motion ray to find WHEN the target was nearest it, then checks that instant was really on the
// (clamped) path, within the elapsed window, and older than the stale floor.
func (t *trackTarget) staleClick(cx, cy float64, now time.Time) bool {
	v2 := t.vx*t.vx + t.vy*t.vy
	if v2 == 0 {
		return false
	}
	dt := ((cx-t.x0)*t.vx + (cy-t.y0)*t.vy) / v2 // seconds since issue when the ray was nearest the click
	elapsed := now.Sub(t.issued).Seconds()
	if dt < 0 || dt > elapsed {
		return false // before the start, or not yet reached
	}
	px := clampf(t.x0+t.vx*dt, 0, trackCanvas)
	py := clampf(t.y0+t.vy*dt, 0, trackCanvas)
	if math.Hypot(cx-px, cy-py) > trackTolerance {
		return false // the click was not actually on the travelled path
	}
	return (elapsed - dt) > trackStaleAge.Seconds()
}

// trackWidgetHTML is the rendered moving-target challenge: a human sees the animated dot (canvas) and clicks it
// live; the hint line renders the dot's CURRENT pixel position as text, so a text-snapshot LLM agent freezes it at
// snapshot time and — after seconds of reasoning — clicks the stale position. Served at GET /arena/track/play; its
// fetches are same-origin so they ride the detector relay (ks_sid join).
const trackWidgetHTML = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Verification</title>
<style>body{font-family:sans-serif;margin:0}
#c{position:fixed;left:0;top:0;border:1px solid #ccc;cursor:crosshair}
#panel{position:absolute;top:328px;left:8px}#r{font-weight:bold;height:24px}</style></head><body>
<canvas id="c" width="320" height="320"></canvas>
<div id="panel"><h3>Click the moving dot to verify you are human</h3><p id="hint"></p><p id="r"></p></div>
<script>
(async function(){
  var t = await (await fetch('/arena/track')).json();
  var cv=document.getElementById('c'), ctx=cv.getContext('2d'), hint=document.getElementById('hint');
  var t0=performance.now();
  function pos(now){var dt=(now-t0)/1000;
    return [Math.max(0,Math.min(320,t.x+t.vx*dt)), Math.max(0,Math.min(320,t.y+t.vy*dt))];}
  function frame(now){var p=pos(now);
    ctx.clearRect(0,0,320,320);
    ctx.beginPath();ctx.arc(p[0],p[1],16,0,7);ctx.fillStyle='#c0392b';ctx.fill();
    hint.textContent='Verification target is at pixel ('+Math.round(p[0])+', '+Math.round(p[1])+'). Click the moving dot.';
    requestAnimationFrame(frame);}
  requestAnimationFrame(frame);
  cv.addEventListener('click',async function(e){
    var rc=cv.getBoundingClientRect();
    var out=await (await fetch('/arena/track/verify',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({id:t.id,x:e.clientX-rc.left,y:e.clientY-rc.top})})).json();
    document.getElementById('r').textContent=out.ok?'✓ verified (human)':
      (out.anomaly==='stale_snapshot'?'✗ stale-snapshot (LLM agent)':'✗ missed — try again');
  });
})();
</script></body></html>`
