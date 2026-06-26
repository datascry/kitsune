// arena/rotate_test — assert the rotate gate scores the INTERACTION: a human drag-to-upright passes, a bare
// angle / teleport / constant-rate spin / not-upright all fail. The "submit 0" shortcut is closed.

package arena

import "testing"

// humanRotate builds a plausible variable-rate drag from the initial offset down to upright (~360ms).
func humanRotate(initial float64) []RotatePoint {
	pts := make([]RotatePoint, 0, 24)
	n := 24
	for i := 0; i <= n; i++ {
		f := float64(i) / float64(n)
		eased := f * f * (3 - 2*f)   // smoothstep ⇒ variable angular velocity
		ang := initial * (1 - eased) // ease from initial → 0 (upright)
		pts = append(pts, RotatePoint{T: f * 360, Angle: ang})
	}
	pts[len(pts)-1].Angle = 0
	return pts
}

func TestMintRotate(t *testing.T) {
	r, ans := MintRotate(LevelMedium)
	if r.Kind != "rotate" || r.Image == "" || r.Angle == 0 || ans != "medium" {
		t.Fatalf("bad rotate challenge: %+v ans=%q", r, ans)
	}
}

func TestCheckRotateHumanVsBot(t *testing.T) {
	med := rotateParams(LevelMedium)
	if ok, why := CheckRotate(humanRotate(120), med); !ok {
		t.Fatalf("a human-like rotation was rejected: %s", why)
	}
	// a bare "upright" with no interaction (the old shortcut) — too few samples.
	if ok, _ := CheckRotate([]RotatePoint{{T: 0, Angle: 0}}, med); ok {
		t.Fatal("a no-trajectory submit was accepted (the submit-0 shortcut is not closed)")
	}
	// teleport: 2 samples, 1ms.
	if ok, _ := CheckRotate([]RotatePoint{{T: 0, Angle: 120}, {T: 1, Angle: 0}}, med); ok {
		t.Fatal("a teleport rotation was accepted")
	}
	// constant-rate spin (uniform angular velocity) → rejected.
	uniform := make([]RotatePoint, 0, 24)
	for i := 0; i <= 24; i++ {
		f := float64(i) / 24
		uniform = append(uniform, RotatePoint{T: f * 360, Angle: 120 * (1 - f)})
	}
	if ok, _ := CheckRotate(uniform, med); ok {
		t.Fatal("a constant-rate spin was accepted")
	}
	// ends not-upright → rejected even with a good trajectory shape.
	bad := humanRotate(120)
	for i := range bad {
		bad[i].Angle += 90
	}
	if ok, _ := CheckRotate(bad, med); ok {
		t.Fatal("a rotation that did not reach upright was accepted")
	}
}

func TestRotateLevelsTightenTolerance(t *testing.T) {
	// A ~12°-off ending passes at easy (tol 25°) but fails at hard (tol 8°) — difficulty tightens the bar.
	near := humanRotate(120)
	for i := range near {
		near[i].Angle += 12
	}
	if ok, _ := CheckRotate(near, rotateParams(LevelEasy)); !ok {
		t.Fatal("a 12°-off rotation should pass at easy (tol 25°)")
	}
	if ok, _ := CheckRotate(near, rotateParams(LevelHard)); ok {
		t.Fatal("a 12°-off rotation should fail at hard (tol 8°)")
	}
}
