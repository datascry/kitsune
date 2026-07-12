// arena/spotdiff_test — tests for the spot-the-difference gate: mint shape + centres, and the match/exactness logic.
// Confirms exact-centroid clicks pass + flag pixel-perfect, near clicks pass without it, and missing a diff fails.

package arena

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMintSpotDiff(t *testing.T) {
	for _, lv := range []Level{LevelEasy, LevelMedium, LevelHard} {
		s, ans := MintSpotDiff(lv)
		_, nDiff := spotParams(lv)
		if s.Kind != "spotdiff" || s.ID == "" || s.Count != nDiff || !strings.HasPrefix(s.Image, "data:image/png;base64,") {
			t.Fatalf("%s: bad shape %+v", lv, s.Kind)
		}
		var centres [][2]int
		if err := json.Unmarshal([]byte(ans), &centres); err != nil || len(centres) != nDiff {
			t.Fatalf("%s: answer not %d centres", lv, nDiff)
		}
	}
}

func TestCheckSpotDiff(t *testing.T) {
	_, ans := MintSpotDiff(LevelMedium)
	var centres [][2]int
	_ = json.Unmarshal([]byte(ans), &centres)

	// pixel-perfect clicks on every centroid -> pass + allExact (an image-diff solve)
	exact := make([][2]float64, len(centres))
	for i, c := range centres {
		exact[i] = [2]float64{float64(c[0]), float64(c[1])}
	}
	if pass, allExact, n := CheckSpotDiff(ans, exact); !pass || !allExact || n != len(centres) {
		t.Errorf("exact clicks: pass=%v allExact=%v (want both true)", pass, allExact)
	}

	// near (human) clicks ~10px off -> pass, but NOT pixel-perfect
	near := make([][2]float64, len(centres))
	for i, c := range centres {
		near[i] = [2]float64{float64(c[0]) + 9, float64(c[1]) - 8}
	}
	if pass, allExact, _ := CheckSpotDiff(ans, near); !pass || allExact {
		t.Errorf("near clicks: pass=%v allExact=%v (want pass, not exact)", pass, allExact)
	}

	// missing one difference (drop the last click) -> fail
	if pass, _, _ := CheckSpotDiff(ans, exact[:len(exact)-1]); pass {
		t.Error("missing a difference must fail")
	}
	// empty target -> fail
	if pass, _, _ := CheckSpotDiff("", exact); pass {
		t.Error("empty target must fail")
	}
}
