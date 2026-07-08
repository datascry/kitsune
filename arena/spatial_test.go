// arena/spatial_test — tests for the 3D spatial cube-grid gate: mint validity + order-independent verify.
// Covers grid size, a guaranteed-solvable answer, PNG tile images, and set-match semantics.

package arena

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestMintSpatial(t *testing.T) {
	for _, lv := range []Level{LevelEasy, LevelMedium, LevelHard} {
		s, ans := MintSpatial(lv)
		if len(s.Tiles) != spatialGridN(lv) {
			t.Errorf("%s: %d tiles, want %d", lv, len(s.Tiles), spatialGridN(lv))
		}
		if ans == "" {
			t.Errorf("%s: empty answer — must guarantee >=1 matching cube", lv)
		}
		if s.Kind != "spatial" || s.ID == "" || !strings.Contains(s.Prompt, "on top") {
			t.Errorf("%s: bad challenge metadata %+v", lv, s)
		}
		for _, tile := range s.Tiles {
			raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(tile.Image, "data:image/png;base64,"))
			if err != nil || len(raw) < 8 || string(raw[1:4]) != "PNG" {
				t.Errorf("%s: tile is not a PNG data URI", lv)
			}
		}
	}
}

func TestCheckSpatial(t *testing.T) {
	cases := []struct {
		expected string
		selected []int
		want     bool
	}{
		{"0,2,5", []int{5, 0, 2}, true}, // order-independent
		{"1", []int{1, 1}, true},        // de-duped
		{"0,2,5", []int{0, 2}, false},   // subset
		{"0,2,5", []int{0, 2, 5, 7}, false},
		{"", []int{}, false}, // no answer stored
	}
	for _, c := range cases {
		if CheckSpatial(c.expected, c.selected) != c.want {
			t.Errorf("CheckSpatial(%q,%v)=%v want %v", c.expected, c.selected, !c.want, c.want)
		}
	}
}
