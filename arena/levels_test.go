// arena/levels_test — guard that every gate's easy/medium/hard is a REAL, monotonic difficulty step-up.
// Regression guard for the image-select medium==hard tile flat-spot; the CV floor is asserted CONSTANT (FP-safe).

package arena

import (
	"testing"

	pow "github.com/datascry/kitsune/evaders/pow"
)

func TestDifficultyLadderIsMonotonic(t *testing.T) {
	e, m, h := LevelEasy, LevelMedium, LevelHard
	up := func(name string, a, b, c int) { // strictly increasing (bigger = harder)
		if !(a < b && b < c) {
			t.Errorf("%s not strictly increasing easy<medium<hard: %d < %d < %d", name, a, b, c)
		}
	}
	upf := func(name string, a, b, c float64) {
		if !(a < b && b < c) {
			t.Errorf("%s not strictly increasing easy<medium<hard: %v < %v < %v", name, a, b, c)
		}
	}
	downf := func(name string, a, b, c float64) { // strictly decreasing (tighter tolerance = harder)
		if !(a > b && b > c) {
			t.Errorf("%s not strictly decreasing easy>medium>hard: %v > %v > %v", name, a, b, c)
		}
	}

	// text: length, speckle, overlap, and TOTAL interference (lines+curves) each rise every level.
	te, tm, th := textParams(e), textParams(m), textParams(h)
	up("text.Length", te.Length, tm.Length, th.Length)
	up("text.Speckle", te.Speckle, tm.Speckle, th.Speckle)
	up("text.Overlap", te.Overlap, tm.Overlap, th.Overlap)
	up("text.interference", te.Lines+te.Curves, tm.Lines+tm.Curves, th.Lines+th.Curves)

	// image-select: BOTH tiles and per-tile noise grow (the medium==hard tile flat-spot this test guards).
	ie, im, ih := imageParams(e), imageParams(m), imageParams(h)
	up("image.Tiles", ie.Tiles, im.Tiles, ih.Tiles)
	up("image.Noise", ie.Noise, im.Noise, ih.Noise)

	// slider/rotate: tolerance tightens, trajectory bar rises; the velocity-CV floor stays CONSTANT (the grounded,
	// FP-safe human-detection bar — a harder level must never raise the false-positive risk on a real person).
	for name, p := range map[string]func(Level) behaviorKnobs{"slider": sliderParams, "rotate": rotateParams} {
		be, bm, bh := p(e), p(m), p(h)
		downf(name+".Tol", be.Tol, bm.Tol, bh.Tol)
		up(name+".MinPts", be.MinPts, bm.MinPts, bh.MinPts)
		upf(name+".MinMs", be.MinMs, bm.MinMs, bh.MinMs)
		if !(be.MinCV == bm.MinCV && bm.MinCV == bh.MinCV) {
			t.Errorf("%s.MinCV must stay CONSTANT across levels (the FP-safe bar): %v %v %v", name, be.MinCV, bm.MinCV, bh.MinCV)
		}
	}

	// PoW: the bit-difficulty rises every level, for every work-function class.
	for _, cls := range []pow.Class{pow.ClassHashcash, pow.ClassManySmall, pow.ClassMemoryHard} {
		de, _, _ := powLevelParams(cls, e)
		dm, _, _ := powLevelParams(cls, m)
		dh, _, _ := powLevelParams(cls, h)
		up("pow."+string(cls), de, dm, dh)
	}

	// queue (waiting-room): the admit-wait cost dial lengthens every level.
	upf("queue.admitWait", float64(queueAdmitWait(e)), float64(queueAdmitWait(m)), float64(queueAdmitWait(h)))
}
