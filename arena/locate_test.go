// arena/locate_test — tests for the point-localization gate: mint shape, acceptance radius, and the distance tell.
// Confirms an exact-centroid click collapses the distance (pixel-perfect), a near click passes, a far click fails.

package arena

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMintLocate(t *testing.T) {
	for _, lv := range []Level{LevelEasy, LevelMedium, LevelHard} {
		l, ans := MintLocate(lv)
		if l.Kind != "locate" || l.ID == "" || !strings.HasPrefix(l.Image, "data:image/png;base64,") {
			t.Fatalf("%s: bad shape %+v", lv, l.Kind)
		}
		var a struct{ CX, CY int }
		if err := json.Unmarshal([]byte(ans), &a); err != nil || a.CX == 0 || a.CY == 0 {
			t.Fatalf("%s: answer not a centre", lv)
		}
		if a.CX < 0 || a.CX > l.Width || a.CY < 0 || a.CY > l.Height {
			t.Errorf("%s: centre %d,%d out of canvas", lv, a.CX, a.CY)
		}
	}
}

func TestCheckLocate(t *testing.T) {
	_, ans := MintLocate(LevelMedium)
	var a struct{ CX, CY int }
	_ = json.Unmarshal([]byte(ans), &a)

	// pixel-perfect click (exact centroid) -> pass, distance ~ 0 (a computed CV click)
	if pass, dist := CheckLocate(ans, a.CX, a.CY); !pass || dist >= localizePixelFloor {
		t.Errorf("exact click: pass=%v dist=%v (want pass, dist < %v)", pass, dist, localizePixelFloor)
	}
	// a human-ish near click (18px off) -> pass, distance well above the pixel floor
	if pass, dist := CheckLocate(ans, a.CX+13, a.CY-12); !pass || dist < localizePixelFloor {
		t.Errorf("near click: pass=%v dist=%v (want pass, dist > %v)", pass, dist, localizePixelFloor)
	}
	// a far click (outside the acceptance radius) -> fail
	if pass, _ := CheckLocate(ans, a.CX+90, a.CY+90); pass {
		t.Error("far click must fail")
	}
	// unknown/empty target -> fail
	if pass, _ := CheckLocate("", a.CX, a.CY); pass {
		t.Error("empty target must fail")
	}
}
