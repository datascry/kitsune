// arena/presshold — press-and-hold gate: hold one button for the shown duration, then release (Cloudflare
// "Press & Hold" / DataDome / HUMAN family). NOVEL server-observed tell: the held-pointer TREMOR — a real finger/
// mouse drifts continuously under a hold (a non-zero jitter floor), while a scripted hold that injects position
// samples pins them to one coordinate (variance ~ 0); plus the claimed-hold-vs-elapsed impossibility.

package arena

import (
	"encoding/json"
	"math"
)

// PressHold is the PUBLIC challenge — the target hold is shown (the client must produce the hold, not guess it).
type PressHold struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Level       string `json:"level"`
	HoldMs      int    `json:"hold_ms"`
	ToleranceMs int    `json:"tolerance_ms"`
	Prompt      string `json:"prompt"`
}

// holdTremorFloor: a held-pointer spatial std (px) below this — WHEN the client reported enough samples to judge —
// is a static, injected hold (no biomechanical drift). Set under any real hand's hold jitter, so it is load-bearing.
const holdTremorFloor = 0.5

// holdMinSamples: the sample count needed before the tremor tell is trusted. A hold that reported fewer (incl. a
// still touch-hold that fires no pointermove) is NOT judged on tremor — only the impossible-timing prong applies,
// which keeps the tell FP-safe for a motionless human touch.
const holdMinSamples = 4

func pressHoldParams(lv Level) (holdMs, tol int) {
	switch lv {
	case LevelEasy:
		return 1500, 400
	case LevelHard:
		return 2500, 180
	default:
		return 2000, 280
	}
}

// MintPressHold builds a single hold target + returns the answer (the target hold + tolerance, referenced by verify).
func MintPressHold(lv Level) (PressHold, string) {
	holdMs, tol := pressHoldParams(lv)
	p := PressHold{
		ID: randHex(16), Kind: "presshold", Level: string(lv), HoldMs: holdMs, ToleranceMs: tol,
		Prompt: "Press and hold the button until it fills for the shown duration, then release.",
	}
	b, _ := json.Marshal(map[string]int{"hold_ms": holdMs, "tol": tol})
	return p, string(b)
}

// CheckPressHold reports whether the achieved hold is within tolerance, the tremor (spatial std of the held-pointer
// samples — the robotic-hold tell), and the sample count. Wrong/unknown target => pass=false.
func CheckPressHold(expected string, heldMs int, samples [][2]float64) (pass bool, tremor float64, n int) {
	var t struct {
		HoldMs int `json:"hold_ms"`
		Tol    int `json:"tol"`
	}
	if err := json.Unmarshal([]byte(expected), &t); err != nil || t.HoldMs == 0 {
		return false, 0, 0
	}
	e := heldMs - t.HoldMs
	pass = e >= -t.Tol && e <= t.Tol
	n = len(samples)
	if n > 0 {
		var mx, my float64
		for _, s := range samples {
			mx += s[0]
			my += s[1]
		}
		mx /= float64(n)
		my /= float64(n)
		var v float64
		for _, s := range samples {
			v += (s[0]-mx)*(s[0]-mx) + (s[1]-my)*(s[1]-my)
		}
		tremor = math.Sqrt(v / float64(n))
	}
	return pass, tremor, n
}
