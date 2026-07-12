// arena/match_test — tests for the orientation-match gate: mint shape, distinct candidate images, answer scoring.
// Confirms the matching candidate passes, a non-matching one fails, and candidate tiles are all distinct PNGs.

package arena

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMintMatch(t *testing.T) {
	for _, lv := range []Level{LevelEasy, LevelMedium, LevelHard} {
		m, ans := MintMatch(lv)
		n, _ := matchParams(lv)
		if m.Kind != "match" || m.ID == "" || len(m.Tiles) != n {
			t.Fatalf("%s: bad shape %+v", lv, m.Kind)
		}
		if !strings.HasPrefix(m.Reference, "data:image/png;base64,") {
			t.Fatalf("%s: reference not a PNG", lv)
		}
		var a struct{ Answer int }
		if err := json.Unmarshal([]byte(ans), &a); err != nil || a.Answer < 0 || a.Answer >= n {
			t.Fatalf("%s: answer index out of range", lv)
		}
		// candidate images are distinct (per-tile jitter + distinct orientations)
		seen := map[string]bool{}
		for _, tile := range m.Tiles {
			if !strings.HasPrefix(tile.Image, "data:image/png;base64,") {
				t.Errorf("%s: tile %d not a PNG", lv, tile.Index)
			}
			if seen[tile.Image] {
				t.Errorf("%s: duplicate tile image", lv)
			}
			seen[tile.Image] = true
		}
	}
}

func TestCheckMatch(t *testing.T) {
	_, ans := MintMatch(LevelMedium)
	var a struct{ Answer int }
	_ = json.Unmarshal([]byte(ans), &a)

	if !CheckMatch(ans, a.Answer) {
		t.Error("the matching candidate must pass")
	}
	if CheckMatch(ans, a.Answer+1) {
		t.Error("a non-matching candidate must fail")
	}
	if CheckMatch("", a.Answer) {
		t.Error("empty target must fail")
	}
}
