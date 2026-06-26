// arena/rotate — a self-hosted ROTATE captcha (Arkose/FunCaptcha-style), owned infra only.
// Verifies the object is upright AND that it was rotated by a real INTERACTION — not a submitted angle.

// The first rotate gate accepted a final angle, so a script just submitted "upright" (0) and won — a
// shortcut. A faithful rotate captcha scores the INTERACTION: a human drags the object around, producing an
// angle trajectory over time. This gate now requires that trajectory and checks it the same way the slider
// does (enough samples, real duration, variable angular velocity — a teleport or constant-rate spin is
// rejected). Submitting a bare angle no longer passes. The behavioural check is on-thesis: it is the same
// uniform-velocity discriminator the detector uses; a synthesized trajectory can still beat it, and then the
// detector convicts the no-JS client anyway. Owned + generic — not a clone of any vendor widget.

package arena

import (
	"math"
	"strings"
)

const (
	rotateTol      = 18  // degrees from upright that count as solved
	rotateMinPts   = 6   // a real drag emits many angle samples; fewer ⇒ a teleport
	rotateMinMs    = 120 // a real rotation takes time
	rotateMinCV    = 0.10
	rotateMinAngle = 40  // initial offset from upright (degrees) — well outside the tolerance
	rotateMaxAngle = 320 // ...up to here
)

// Rotate is the PUBLIC challenge. Image is an upright arrow the page renders rotated by Angle; the human
// rotates it back to upright by dragging (producing the trajectory the gate scores).
type Rotate struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Image string `json:"image"`
	Angle int    `json:"angle"`
}

// RotatePoint is one captured sample during the rotation drag (t in ms since start, angle in degrees).
type RotatePoint struct {
	T     float64 `json:"t"`
	Angle float64 `json:"angle"`
}

// arrowSVG renders an upright arrow (pointing up); the page rotates it by the initial angle and the human
// drags it back to upright.
func arrowSVG() string {
	svg := `<svg xmlns="http://www.w3.org/2000/svg" width="90" height="90"><polygon points="45,10 70,55 50,55 50,80 40,80 40,55 20,55" fill="#7a5cff"/></svg>`
	return "data:image/svg+xml;utf8," + strings.NewReplacer("#", "%23").Replace(svg)
}

// MintRotate builds a fresh rotate challenge at the given level with a random initial offset from upright.
// The stored verify state is the level string (the trajectory bar + upright tolerance depend on it).
func MintRotate(lv Level) (Rotate, string) {
	angle := rotateMinAngle + int(randInt(int64(rotateMaxAngle-rotateMinAngle)))
	return Rotate{Kind: "rotate", ID: randHex(16), Image: arrowSVG(), Angle: angle}, string(lv)
}

// distToUpright returns the angular distance (0..180) of a (mod-360) angle from upright.
func distToUpright(a float64) float64 {
	d := math.Mod(math.Abs(a), 360)
	if d > 180 {
		d = 360 - d
	}
	return d
}

// CheckRotate reports whether the object ended upright AND was rotated by a human-like drag. Fails a teleport
// (too few samples / too fast) and a constant-rate spin (angular-velocity CV below the floor). Returns
// (ok, reason). The final orientation is taken from the trajectory's last sample, so a bare angle with no
// trajectory cannot pass.
func CheckRotate(traj []RotatePoint, k behaviorKnobs) (bool, string) {
	if len(traj) < k.MinPts {
		return false, "no real rotation (submit a drag, not an angle)"
	}
	if distToUpright(traj[len(traj)-1].Angle) > k.Tol {
		return false, "not upright"
	}
	if traj[len(traj)-1].T-traj[0].T < k.MinMs {
		return false, "rotation too fast to be human"
	}
	vs := make([]float64, 0, len(traj)-1)
	for i := 1; i < len(traj); i++ {
		dt := traj[i].T - traj[i-1].T
		if dt <= 0 {
			continue
		}
		vs = append(vs, math.Abs(traj[i].Angle-traj[i-1].Angle)/dt)
	}
	if cvOf(vs) < k.MinCV {
		return false, "rotation rate too uniform (synthetic)"
	}
	return true, "ok"
}
