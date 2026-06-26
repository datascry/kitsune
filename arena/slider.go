// arena/slider — a self-hosted SLIDER captcha (GeeTest-style drag-to-fit), owned infra only.
// Verifies the drop position AND the drag trajectory's behavioural plausibility — vendor-neutral, no clone.

// The slider is the standout modern interactive CAPTCHA: a visitor drags a puzzle piece into a gap. A faithful
// reproduction verifies TWO things, like the real ones: (1) the piece landed in the gap, and (2) the DRAG was
// human — a real drag has variable velocity, a scripted one is a constant-velocity glide or a teleport. That
// second check is exactly Kitsune's `uniform_velocity` behavioural tell, so the slider gate is on-thesis: the
// trajectory is the discriminator, and a bot that submits the right X with a robotic drag is caught here (and
// again, deeper, by the detector). Generic + self-hosted — not a clone of any vendor's widget.

package arena

import (
	"math"
)

const (
	sliderTrackW  = 300 // px — the draggable track width the page renders
	sliderPieceW  = 42  // px — the puzzle-piece width
	sliderTol     = 8   // px — how close to the gap counts as a fit
	sliderMinPts  = 6   // a real drag emits many pointermove samples; fewer ⇒ a teleport/synthetic jump
	sliderMinMs   = 120 // a real drag takes time; an instant "drag" is a script
	sliderMinCV   = 0.12
	sliderMaxGapX = sliderTrackW - sliderPieceW - 20
	sliderMinGapX = 90
)

// Slider is the PUBLIC challenge. GapX is where the piece must land — it is visible in the rendered track
// anyway (as in every real slider captcha), so the discriminator is the DRAG, not secrecy of the target.
type Slider struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	GapX   int    `json:"gap_x"`
	TrackW int    `json:"track_w"`
	PieceW int    `json:"piece_w"`
}

// SliderPoint is one captured pointer sample during the drag (t in ms since drag start, x in px).
type SliderPoint struct {
	T float64 `json:"t"`
	X float64 `json:"x"`
}

// MintSlider builds a fresh slider challenge and returns it with the target gap X (stored for verify).
func MintSlider() (Slider, string) {
	gap := sliderMinGapX + int(randInt(int64(sliderMaxGapX-sliderMinGapX)))
	return Slider{Kind: "slider", ID: randHex(16), GapX: gap, TrackW: sliderTrackW, PieceW: sliderPieceW},
		// the stored "answer" is the gap X as a string, reusing the captcha store
		itoa(gap)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// CheckSlider reports whether the drag fits the gap AND looks human. It fails a teleport (too few points / too
// fast) and a constant-velocity robotic glide (velocity coefficient-of-variation below the floor) — the same
// uniform-velocity discriminator the detector uses. Returns (ok, reason) so the page can explain a rejection.
func CheckSlider(gapX int, finalX float64, traj []SliderPoint) (bool, string) {
	if math.Abs(finalX-float64(gapX)) > sliderTol {
		return false, "missed the gap"
	}
	if len(traj) < sliderMinPts {
		return false, "no real drag (teleport)"
	}
	dur := traj[len(traj)-1].T - traj[0].T
	if dur < sliderMinMs {
		return false, "drag too fast to be human"
	}
	// Per-segment velocity; a human drag accelerates then settles (high CV), a script gli­des at one speed (CV~0).
	vs := make([]float64, 0, len(traj)-1)
	for i := 1; i < len(traj); i++ {
		dt := traj[i].T - traj[i-1].T
		if dt <= 0 {
			continue
		}
		vs = append(vs, math.Abs(traj[i].X-traj[i-1].X)/dt)
	}
	if cvOf(vs) < sliderMinCV {
		return false, "drag velocity too uniform (synthetic)"
	}
	return true, "ok"
}

// cvOf returns the coefficient of variation (std/mean) of the samples, or 0 for a degenerate set.
func cvOf(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean := sum / float64(len(xs))
	if mean == 0 {
		return 0
	}
	var ss float64
	for _, x := range xs {
		ss += (x - mean) * (x - mean)
	}
	return math.Sqrt(ss/float64(len(xs))) / mean
}
