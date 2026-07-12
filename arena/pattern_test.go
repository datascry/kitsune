// arena/pattern_test — tests for the trace-the-pattern gate: mint shape, in-order stroke pass, deviation tell.
// Confirms a perfectly straight synthetic stroke collapses the deviation while a wobbly human stroke does not.

package arena

import (
	"encoding/json"
	"math"
	"testing"
)

func TestMintPattern(t *testing.T) {
	for _, lv := range []Level{LevelEasy, LevelMedium, LevelHard} {
		p, ans := MintPattern(lv)
		n := patternParams(lv)
		if p.Kind != "pattern" || p.ID == "" || len(p.Dots) != n || p.Radius != patternHitRadius {
			t.Fatalf("%s: bad shape %+v", lv, p.Kind)
		}
		var dots []PatternDot
		if err := json.Unmarshal([]byte(ans), &dots); err != nil || len(dots) != n {
			t.Fatalf("%s: answer not the dots", lv)
		}
	}
}

// straightStroke walks the polyline through the dots with a fixed step, offsetting each point perpendicular by wob.
func strokeThrough(dots []PatternDot, step float64, wob func(i int) float64) [][2]float64 {
	var out [][2]float64
	k := 0
	for i := 0; i < len(dots)-1; i++ {
		ax, ay := float64(dots[i].X), float64(dots[i].Y)
		bx, by := float64(dots[i+1].X), float64(dots[i+1].Y)
		dx, dy := bx-ax, by-ay
		L := math.Hypot(dx, dy)
		nx, ny := -dy/L, dx/L // unit normal
		for d := 0.0; d < L; d += step {
			t := d / L
			w := wob(k)
			k++
			out = append(out, [2]float64{ax + t*dx + w*nx, ay + t*dy + w*ny})
		}
	}
	last := dots[len(dots)-1]
	out = append(out, [2]float64{float64(last.X), float64(last.Y)})
	return out
}

func TestCheckPattern(t *testing.T) {
	_, ans := MintPattern(LevelHard)
	var dots []PatternDot
	_ = json.Unmarshal([]byte(ans), &dots)

	// a perfectly straight synthetic stroke -> pass, mean deviation ~ 0 (too straight)
	if pass, dev, n := CheckPattern(ans, strokeThrough(dots, 4, func(int) float64 { return 0 })); !pass || dev >= patternStraightPx || n != len(dots) {
		t.Errorf("straight stroke: pass=%v dev=%v (want pass, dev < %v)", pass, dev, patternStraightPx)
	}
	// a wobbly human stroke (alternating +/-5px normal offset) -> pass, deviation well above the floor
	human := strokeThrough(dots, 4, func(i int) float64 {
		if i%2 == 0 {
			return 5
		}
		return -5
	})
	if pass, dev, _ := CheckPattern(ans, human); !pass || dev < patternStraightPx {
		t.Errorf("wobbly stroke: pass=%v dev=%v (want pass, dev > %v)", pass, dev, patternStraightPx)
	}
	// a stroke that misses the waypoints (a flat line off to the side) -> fail the order check
	miss := [][2]float64{{0, 0}, {1, 0}, {2, 0}}
	if pass, _, _ := CheckPattern(ans, miss); pass {
		t.Error("a stroke missing the waypoints must fail")
	}
	// too-short / empty stroke -> fail
	if pass, _, _ := CheckPattern(ans, [][2]float64{{1, 1}}); pass {
		t.Error("a single-point stroke must fail")
	}
	if pass, _, _ := CheckPattern("", human); pass {
		t.Error("empty target must fail")
	}
}
