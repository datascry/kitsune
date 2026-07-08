// arena/timing_test — tests for the motor-timing gate: mint shape, tolerance scoring, and the release-error std.
// Confirms a superhuman (target-exact / constant-offset) solve collapses the std while a jittered human solve does not.

package arena

import (
	"encoding/json"
	"testing"
)

func TestMintTiming(t *testing.T) {
	for _, lv := range []Level{LevelEasy, LevelMedium, LevelHard} {
		tm, ans := MintTiming(lv)
		n, minH, maxH, tol := timingParams(lv)
		if tm.Kind != "timing" || tm.ID == "" || len(tm.Targets) != n {
			t.Fatalf("%s: bad shape %+v", lv, tm)
		}
		var targets []TimingTarget
		if err := json.Unmarshal([]byte(ans), &targets); err != nil || len(targets) != n {
			t.Fatalf("%s: answer not the targets JSON", lv)
		}
		for _, tg := range tm.Targets {
			if tg.HoldMs < minH || tg.HoldMs >= maxH || tg.ToleranceMs != tol {
				t.Errorf("%s: target out of range %+v", lv, tg)
			}
		}
	}
}

func TestCheckTiming(t *testing.T) {
	_, ans := MintTiming(LevelMedium)
	var targets []TimingTarget
	_ = json.Unmarshal([]byte(ans), &targets)

	// perfect (target-exact) holds -> pass, std == 0 (superhuman)
	exact := make([]int, len(targets))
	for i, tg := range targets {
		exact[i] = tg.HoldMs
	}
	if pass, std, _ := CheckTiming(ans, exact); !pass || std != 0 {
		t.Errorf("exact holds: pass=%v std=%v (want pass, std 0)", pass, std)
	}

	// constant offset (+40ms) -> still pass (within tol 180), std STILL 0 (flat) -> caught by the same floor
	off := make([]int, len(targets))
	for i, tg := range targets {
		off[i] = tg.HoldMs + 40
	}
	if pass, std, _ := CheckTiming(ans, off); !pass || std != 0 {
		t.Errorf("constant offset: pass=%v std=%v (want pass, std 0)", pass, std)
	}

	// human-like jitter -> pass, std well above the floor
	jit := []int{-90, 70, -40, 110, -60}[:len(targets)]
	human := make([]int, len(targets))
	sum := 0.0
	for i, tg := range targets {
		human[i] = tg.HoldMs + jit[i]
		sum += float64(jit[i])
	}
	if pass, std, total := CheckTiming(ans, human); !pass || std < timingPrecisionFloorMs || total <= 0 {
		t.Errorf("jittered human: pass=%v std=%v (want pass, std > %v)", pass, std, timingPrecisionFloorMs)
	}

	// out of tolerance -> fail
	bad := make([]int, len(targets))
	for i, tg := range targets {
		bad[i] = tg.HoldMs + tg.ToleranceMs + 500
	}
	if pass, _, _ := CheckTiming(ans, bad); pass {
		t.Error("out-of-tolerance holds must fail")
	}
	// wrong count -> fail
	if pass, _, _ := CheckTiming(ans, []int{1}); pass {
		t.Error("wrong hold count must fail")
	}
}
