// arena/sequence_test — tests for the ordered click-in-sequence gate: mint shape, order scoring, cadence std.
// Confirms a correct-order solve passes, a wrong order fails, and a metronomic cadence collapses the std.

package arena

import (
	"encoding/json"
	"testing"
)

func TestMintSequence(t *testing.T) {
	for _, lv := range []Level{LevelEasy, LevelMedium, LevelHard} {
		s, ans := MintSequence(lv)
		n := seqParams(lv)
		if s.Kind != "sequence" || s.ID == "" || len(s.Tiles) != n {
			t.Fatalf("%s: bad shape %+v", lv, s)
		}
		var order []int
		if err := json.Unmarshal([]byte(ans), &order); err != nil || len(order) != n {
			t.Fatalf("%s: answer not the order JSON", lv)
		}
		// tiles carry the labels 1..n exactly once
		seen := map[int]bool{}
		for _, tile := range s.Tiles {
			if tile.ID < 1 || tile.ID > n || seen[tile.ID] {
				t.Errorf("%s: bad tile id %d", lv, tile.ID)
			}
			seen[tile.ID] = true
		}
	}
}

func TestCheckSequence(t *testing.T) {
	_, ans := MintSequence(LevelHard) // n = 5
	var order []int
	_ = json.Unmarshal([]byte(ans), &order)

	// correct order with human-varied timestamps -> pass, cadence std above the floor
	humanT := []int{0, 480, 1010, 1620, 2050}
	if pass, n, std := CheckSequence(ans, order, humanT); !pass || n != 5 || std < seqCadenceFloorMs {
		t.Errorf("human solve: pass=%v n=%v std=%v (want pass, std > %v)", pass, n, std, seqCadenceFloorMs)
	}

	// metronomic (fixed 100ms gap) -> pass the gate, cadence std ~ 0 (robotic)
	metro := []int{0, 100, 200, 300, 400}
	if pass, _, std := CheckSequence(ans, order, metro); !pass || std >= seqCadenceFloorMs {
		t.Errorf("metronomic: pass=%v std=%v (want pass, std < %v)", pass, std, seqCadenceFloorMs)
	}

	// wrong order -> fail
	bad := append([]int{}, order...)
	bad[0], bad[1] = bad[1], bad[0]
	if pass, _, _ := CheckSequence(ans, bad, metro); pass {
		t.Error("wrong order must fail")
	}
	// wrong count -> fail; empty target -> fail
	if pass, _, _ := CheckSequence(ans, []int{1}, nil); pass {
		t.Error("wrong count must fail")
	}
	if pass, _, _ := CheckSequence("", order, nil); pass {
		t.Error("empty target must fail")
	}
}
