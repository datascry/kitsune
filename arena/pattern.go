// arena/pattern — connect-the-dots / trace-the-pattern gate: draw one stroke through N waypoints in order (the
// Android-pattern-lock / trace-the-shape family). NOVEL server-observed tell: PATH FIDELITY — a synthetic stroke
// hugs the ideal polyline with ~0 mean deviation (too straight for a human hand, which wobbles), plus superhuman
// speed (drawing through N waypoints faster than a human can move the pointer between them).

package arena

import (
	"encoding/json"
	"math"
)

// PatternDot is one waypoint the stroke must pass through, in order.
type PatternDot struct {
	Index int `json:"index"`
	X     int `json:"x"`
	Y     int `json:"y"`
}

// Pattern is the PUBLIC challenge — the ordered dots are shown; the task is DRAWING the stroke through them, so the
// solve-behaviour (fidelity + speed) discriminates, not a secret.
type Pattern struct {
	ID     string       `json:"id"`
	Kind   string       `json:"kind"`
	Level  string       `json:"level"`
	Dots   []PatternDot `json:"dots"`
	Radius int          `json:"radius"`
	Prompt string       `json:"prompt"`
}

const (
	patternHitRadius   = 26  // the stroke must pass within this of each waypoint to "hit" it (generous for humans)
	patternStraightPx  = 1.5 // mean stroke deviation from the ideal polyline below this is a synthetic (too-straight) path
	patternPerWaypoint = 300 // ms a human needs to move the pointer between consecutive waypoints
)

func patternParams(lv Level) (n int) {
	switch lv {
	case LevelEasy:
		return 3
	case LevelHard:
		return 5
	default:
		return 4
	}
}

// MintPattern places N waypoints at spread positions + returns the answer (the ordered waypoints, referenced by
// verify to check order, deviation, and speed).
func MintPattern(lv Level) (Pattern, string) {
	n := patternParams(lv)
	dots := make([]PatternDot, n)
	for i := range dots {
		dots[i] = PatternDot{Index: i, X: 30 + int(randInt(260)), Y: 30 + int(randInt(160))}
	}
	p := Pattern{
		ID: randHex(16), Kind: "pattern", Level: string(lv), Dots: dots, Radius: patternHitRadius,
		Prompt: "Draw one line through the dots in order (1, 2, 3, …) without lifting.",
	}
	ans, _ := json.Marshal(dots)
	return p, string(ans)
}

func pointSegDist(px, py, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	if dx == 0 && dy == 0 {
		return math.Hypot(px-ax, py-ay)
	}
	t := ((px-ax)*dx + (py-ay)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(ax+t*dx), py-(ay+t*dy))
}

// CheckPattern replays the stroke: it must pass within patternHitRadius of every waypoint IN ORDER. Returns the
// mean deviation of the stroke from the ideal polyline (the path-fidelity tell) and the waypoint count.
func CheckPattern(expected string, stroke [][2]float64) (pass bool, meanDev float64, n int) {
	var dots []PatternDot
	if err := json.Unmarshal([]byte(expected), &dots); err != nil || len(dots) == 0 || len(stroke) < 2 {
		return false, 0, 0
	}
	n = len(dots)
	// order check: advance through the waypoints as the stroke reaches each within the hit radius
	wp := 0
	for _, s := range stroke {
		if wp < n && math.Hypot(s[0]-float64(dots[wp].X), s[1]-float64(dots[wp].Y)) <= patternHitRadius {
			wp++
		}
	}
	pass = wp == n
	// mean deviation from the ideal polyline (nearest segment for each stroke point)
	var sum float64
	for _, s := range stroke {
		best := math.Inf(1)
		for i := 0; i < n-1; i++ {
			d := pointSegDist(s[0], s[1], float64(dots[i].X), float64(dots[i].Y), float64(dots[i+1].X), float64(dots[i+1].Y))
			if d < best {
				best = d
			}
		}
		sum += best
	}
	meanDev = sum / float64(len(stroke))
	return pass, meanDev, n
}
