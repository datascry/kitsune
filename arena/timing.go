// arena/timing — motor-timing-precision gate: hold/release each target for its shown duration, within tolerance.
// NOVEL server-observed tell: the release-error std across targets — a bot is superhumanly precise (std ~ 0) or a
// flat constant offset (std ~ 0); a human has an irreducible biomechanical jitter floor. Also the claimed-vs-elapsed
// impossibility (total hold time > the server-observed solve window).

package arena

import (
	"encoding/json"
	"math"
)

// TimingTarget is one hold: press and release after HoldMs, within +/- ToleranceMs.
type TimingTarget struct {
	Index       int `json:"index"`
	HoldMs      int `json:"hold_ms"`
	ToleranceMs int `json:"tolerance_ms"`
}

// Timing is the PUBLIC challenge — the targets are shown (the client must produce the timing, not guess a secret).
type Timing struct {
	ID      string         `json:"id"`
	Kind    string         `json:"kind"`
	Level   string         `json:"level"`
	Targets []TimingTarget `json:"targets"`
	Prompt  string         `json:"prompt"`
}

// timingPrecisionFloorMs: a release-error std below this across the targets is superhuman motor precision. Set well
// under any real human's hold-and-release jitter (tens of ms), so precision 1.0 is load-bearing (FP-safe).
const timingPrecisionFloorMs = 25.0

func timingParams(lv Level) (n, minHold, maxHold, tol int) {
	switch lv {
	case LevelEasy:
		return 4, 800, 1600, 250
	case LevelHard:
		return 6, 900, 2400, 120
	default:
		return 5, 800, 2000, 180
	}
}

// MintTiming builds N hold targets + returns the answer (the targets as JSON — the verify references them to score
// tolerance, the release-error std, and the total hold time).
func MintTiming(lv Level) (Timing, string) {
	n, minH, maxH, tol := timingParams(lv)
	targets := make([]TimingTarget, n)
	for i := range targets {
		targets[i] = TimingTarget{Index: i, HoldMs: minH + int(randInt(int64(maxH-minH))), ToleranceMs: tol}
	}
	t := Timing{
		ID: randHex(16), Kind: "timing", Level: string(lv), Targets: targets,
		Prompt: "Press and hold each target for the shown duration, then release — as precisely as you can.",
	}
	b, _ := json.Marshal(targets)
	return t, string(b)
}

// CheckTiming reports whether every hold is within tolerance, the release-error std (the precision tell), and the
// total claimed hold time (the server-observed floor). Wrong count or any out-of-tolerance hold => pass=false.
func CheckTiming(expected string, holds []int) (pass bool, errStd float64, sumHold int) {
	var targets []TimingTarget
	if err := json.Unmarshal([]byte(expected), &targets); err != nil || len(holds) != len(targets) || len(targets) == 0 {
		return false, 0, 0
	}
	errs := make([]float64, len(targets))
	pass = true
	for i, t := range targets {
		e := holds[i] - t.HoldMs
		if e < -t.ToleranceMs || e > t.ToleranceMs {
			pass = false
		}
		errs[i] = float64(e)
		sumHold += holds[i]
	}
	// std of the release errors: a constant-offset bot AND a target-exact bot both collapse to std ~ 0.
	var mean float64
	for _, e := range errs {
		mean += e
	}
	mean /= float64(len(errs))
	var v float64
	for _, e := range errs {
		v += (e - mean) * (e - mean)
	}
	errStd = math.Sqrt(v / float64(len(errs)))
	return pass, errStd, sumHold
}
