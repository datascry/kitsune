// arena/reaction_test — tests for the reaction-time gate: mint delay range + the reaction-latency floor scoring.
// Confirms a human-plausible reaction passes, a superhuman one fails, and an anticipatory (pre-go) click is negative.

package arena

import (
	"strconv"
	"testing"
)

func TestMintReaction(t *testing.T) {
	for _, lv := range []Level{LevelEasy, LevelMedium, LevelHard} {
		r, ans := MintReaction(lv)
		minD, maxD := reactionParams(lv)
		if r.Kind != "reaction" || r.ID == "" || r.DelayMs < minD || r.DelayMs >= maxD {
			t.Fatalf("%s: bad shape %+v", lv, r)
		}
		if d, err := strconv.Atoi(ans); err != nil || d != r.DelayMs {
			t.Fatalf("%s: answer not the delay", lv)
		}
	}
}

func TestCheckReaction(t *testing.T) {
	_, ans := MintReaction(LevelMedium)
	delay, _ := strconv.Atoi(ans)

	// a human-plausible reaction (~260ms after the go) -> pass, reaction above the floor
	if pass, react := CheckReaction(ans, delay+260); !pass || react < reactionFloorMs {
		t.Errorf("human reaction: pass=%v react=%v (want pass, >= %v)", pass, react, reactionFloorMs)
	}
	// a superhuman reaction (40ms after the go) -> fail (convicts)
	if pass, react := CheckReaction(ans, delay+40); pass || react >= reactionFloorMs {
		t.Errorf("superhuman: pass=%v react=%v (want fail, < %v)", pass, react, reactionFloorMs)
	}
	// an anticipatory click (reached the server BEFORE the go) -> negative reaction, fail
	if pass, react := CheckReaction(ans, delay-80); pass || react >= 0 {
		t.Errorf("anticipation: pass=%v react=%v (want fail, negative)", pass, react)
	}
	// unparseable target -> fail
	if pass, _ := CheckReaction("nan", delay+260); pass {
		t.Error("unparseable target must fail")
	}
}
