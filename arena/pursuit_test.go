// arena/pursuit_test — tests for the smooth-pursuit gate: mint shape + the tracking-error scoring.
// Confirms a perfect follow collapses the error (superhuman), a jittery human follow passes above the floor, a
// loose follow fails, and too few samples fail.

package arena

import (
	"encoding/json"
	"testing"
)

func TestMintPursuit(t *testing.T) {
	for _, lv := range []Level{LevelEasy, LevelMedium, LevelHard} {
		p, ans := MintPursuit(lv)
		if p.Kind != "pursuit" || p.ID == "" || p.DurationMs != pursuitParams(lv) {
			t.Fatalf("%s: bad shape %+v", lv, p.Kind)
		}
		var a struct {
			Path PursuitPath
			Dur  int
		}
		if err := json.Unmarshal([]byte(ans), &a); err != nil || a.Dur != p.DurationMs {
			t.Fatalf("%s: answer not the path", lv)
		}
	}
}

// followSamples generates cursor samples along the target path with a fixed perpendicular-ish offset (jitter).
func followSamples(path PursuitPath, dur, step int, jit float64) []PursuitSample {
	var out []PursuitSample
	sign := 1.0
	for t := 0; t <= dur; t += step {
		x, y := path.pos(float64(t))
		out = append(out, PursuitSample{T: float64(t), X: x + jit*sign, Y: y - jit*sign})
		sign = -sign
	}
	return out
}

func TestCheckPursuit(t *testing.T) {
	_, ans := MintPursuit(LevelMedium)
	var a struct {
		Path PursuitPath
		Dur  int
	}
	_ = json.Unmarshal([]byte(ans), &a)

	// a perfect follow (zero offset) -> pass, mean error ~ 0 (superhuman)
	if pass, err, n := CheckPursuit(ans, followSamples(a.Path, a.Dur, 100, 0)); !pass || err >= pursuitErrorFloor || n < pursuitMinSamples {
		t.Errorf("perfect follow: pass=%v err=%v (want pass, err < %v)", pass, err, pursuitErrorFloor)
	}
	// a jittery human follow (~25px offset) -> pass, error above the superhuman floor but below the pass max
	if pass, err, _ := CheckPursuit(ans, followSamples(a.Path, a.Dur, 100, 25)); !pass || err < pursuitErrorFloor {
		t.Errorf("human follow: pass=%v err=%v (want pass, err > %v)", pass, err, pursuitErrorFloor)
	}
	// a loose follow (way off) -> did not track, fail the gate
	if pass, _, _ := CheckPursuit(ans, followSamples(a.Path, a.Dur, 100, 120)); pass {
		t.Error("a loose follow must fail the gate")
	}
	// too few samples -> fail
	if pass, _, _ := CheckPursuit(ans, followSamples(a.Path, a.Dur, 1000, 0)); pass {
		t.Error("too few samples must fail")
	}
	// unparseable target -> fail
	if pass, _, _ := CheckPursuit("", followSamples(a.Path, a.Dur, 100, 0)); pass {
		t.Error("empty target must fail")
	}
}
