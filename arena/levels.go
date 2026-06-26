// arena/levels — per-gate difficulty (easy/medium/hard) as a COST dial, not a security dial.
// Harder gates raise the attacker's cost; they never discriminate bots from humans (the detector does that).

// The arena's whole thesis is that a solved challenge is not a bot/human test. So difficulty here is honest
// about what it changes: more PoW work, heavier text distortion, tighter fit, a richer required trajectory —
// the COST of passing, never the coherence verdict. The detector convicts a scripted client at EVERY level.
// honeypot and pact have no difficulty axis (they are binary) and ignore the level. For the behavioural gates
// (slider/rotate) the velocity-CV floor — the actual human-detection bar, grounded on real human data — stays
// CONSTANT across levels; difficulty tightens the fit tolerance and asks for a richer trajectory, both within
// human reach, so a harder level never false-positives a real person.

package arena

// Level is a gate's difficulty tier.
type Level string

const (
	LevelEasy   Level = "easy"
	LevelMedium Level = "medium"
	LevelHard   Level = "hard"
)

// ParseLevel maps a query value to a Level, defaulting to medium for empty/unknown input.
func ParseLevel(s string) Level {
	switch Level(s) {
	case LevelEasy:
		return LevelEasy
	case LevelHard:
		return LevelHard
	default:
		return LevelMedium
	}
}

// textKnobs parametrise the rasterised text gate: more characters, stronger warp, denser noise, and (at hard)
// a confusable alphabet make OCR progressively harder.
type textKnobs struct {
	Length     int
	WarpAmp    float64 // base sine-warp amplitude (px)
	Speckle    int     // number of noise pixels
	Lines      int     // number of noise strokes
	Confusable bool    // include visually ambiguous glyphs (0/O, 1/I/L) — only at hard
}

func textParams(lv Level) textKnobs {
	switch lv {
	case LevelEasy:
		return textKnobs{Length: 4, WarpAmp: 2, Speckle: 25, Lines: 1, Confusable: false}
	case LevelHard:
		return textKnobs{Length: 6, WarpAmp: 7, Speckle: 140, Lines: 3, Confusable: true}
	default:
		return textKnobs{Length: 5, WarpAmp: 4, Speckle: 70, Lines: 2, Confusable: false}
	}
}

// imageKnobs parametrise the image-select grid: more tiles + heavier per-tile noise make the CV classification
// harder.
type imageKnobs struct {
	Tiles int
	Noise int // speckle pixels per tile
}

func imageParams(lv Level) imageKnobs {
	switch lv {
	case LevelEasy:
		return imageKnobs{Tiles: 6, Noise: 20}
	case LevelHard:
		return imageKnobs{Tiles: 9, Noise: 120}
	default:
		return imageKnobs{Tiles: 9, Noise: 45}
	}
}

// behaviorKnobs parametrise the slider/rotate behavioural gates. MinCV (the velocity-uniformity floor) is the
// grounded human-detection bar and is held CONSTANT across levels for FP-safety; difficulty tightens Tol and
// raises MinPts/MinMs — a richer drag a human still produces easily, but a lazy synthetic must work harder for.
type behaviorKnobs struct {
	Tol    float64 // position/angle tolerance
	MinPts int     // minimum trajectory samples
	MinMs  float64 // minimum drag duration
	MinCV  float64 // velocity coefficient-of-variation floor (constant — grounded, FP-safe)
}

func sliderParams(lv Level) behaviorKnobs {
	switch lv {
	case LevelEasy:
		return behaviorKnobs{Tol: 12, MinPts: 5, MinMs: 80, MinCV: sliderMinCV}
	case LevelHard:
		return behaviorKnobs{Tol: 4, MinPts: 12, MinMs: 300, MinCV: sliderMinCV}
	default: // medium = the grounded baseline constants
		return behaviorKnobs{Tol: sliderTol, MinPts: sliderMinPts, MinMs: sliderMinMs, MinCV: sliderMinCV}
	}
}

func rotateParams(lv Level) behaviorKnobs {
	switch lv {
	case LevelEasy:
		return behaviorKnobs{Tol: 25, MinPts: 5, MinMs: 80, MinCV: rotateMinCV}
	case LevelHard:
		return behaviorKnobs{Tol: 8, MinPts: 12, MinMs: 300, MinCV: rotateMinCV}
	default: // medium = the grounded baseline constants
		return behaviorKnobs{Tol: rotateTol, MinPts: rotateMinPts, MinMs: rotateMinMs, MinCV: rotateMinCV}
	}
}
