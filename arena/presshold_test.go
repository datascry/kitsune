// arena/presshold_test — tests for the press-and-hold gate: mint shape, tolerance scoring, and the tremor tell.
// Confirms a static (injected-coordinate) hold collapses the tremor to ~0 while a drifting human hold does not.

package arena

import (
	"encoding/json"
	"testing"
)

func TestMintPressHold(t *testing.T) {
	for _, lv := range []Level{LevelEasy, LevelMedium, LevelHard} {
		p, ans := MintPressHold(lv)
		holdMs, tol := pressHoldParams(lv)
		if p.Kind != "presshold" || p.ID == "" || p.HoldMs != holdMs || p.ToleranceMs != tol {
			t.Fatalf("%s: bad shape %+v", lv, p)
		}
		var a struct {
			HoldMs int `json:"hold_ms"`
			Tol    int `json:"tol"`
		}
		if err := json.Unmarshal([]byte(ans), &a); err != nil || a.HoldMs != holdMs || a.Tol != tol {
			t.Fatalf("%s: answer not the target JSON", lv)
		}
	}
}

func TestCheckPressHold(t *testing.T) {
	_, ans := MintPressHold(LevelMedium)
	holdMs, _ := pressHoldParams(LevelMedium)

	// a drifting human hold (samples spread around a point) -> pass, tremor well above the floor
	human := [][2]float64{{100, 100}, {101.4, 99.2}, {99.1, 101.8}, {100.7, 100.3}, {98.6, 99.9}, {101.9, 100.6}}
	if pass, tremor, n := CheckPressHold(ans, holdMs, human); !pass || tremor < holdTremorFloor || n != len(human) {
		t.Errorf("human hold: pass=%v tremor=%v (want pass, tremor > %v)", pass, tremor, holdTremorFloor)
	}

	// a static injected hold (all samples pinned to one coordinate) -> pass the gate, tremor ~ 0 (robotic)
	static := make([][2]float64, 8)
	for i := range static {
		static[i] = [2]float64{200, 200}
	}
	if pass, tremor, _ := CheckPressHold(ans, holdMs, static); !pass || tremor >= holdTremorFloor {
		t.Errorf("static hold: pass=%v tremor=%v (want pass, tremor < %v)", pass, tremor, holdTremorFloor)
	}

	// out of tolerance -> fail
	if pass, _, _ := CheckPressHold(ans, holdMs+5000, human); pass {
		t.Error("out-of-tolerance hold must fail")
	}
	// unknown/empty target -> fail
	if pass, _, _ := CheckPressHold("", holdMs, human); pass {
		t.Error("empty target must fail")
	}
}
