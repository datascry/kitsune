// arena/pursuit — smooth-pursuit tracking gate: keep the cursor on a continuously MOVING dot for a few seconds.
// NOVEL server-observed tell: the mean tracking error against the (public, deterministic) path. Human smooth
// pursuit trails a moving target with tens of px of error (visuomotor lag + jitter); a bot that computes the path
// holds the cursor within a few px — superhuman tracking accuracy. Distinct from `track` (stale-snapshot click).

package arena

import (
	"encoding/json"
	"math"
)

// PursuitPath is the deterministic Lissajous target path — PUBLIC (the client renders the dot from it); the task is
// FOLLOWING the visible dot, so the tracking-accuracy discriminates, not knowledge of the path.
type PursuitPath struct {
	CX float64 `json:"cx"`
	CY float64 `json:"cy"`
	A  float64 `json:"a"`
	B  float64 `json:"b"`
	W1 float64 `json:"w1"`
	W2 float64 `json:"w2"`
	P1 float64 `json:"p1"`
	P2 float64 `json:"p2"`
}

type Pursuit struct {
	ID         string      `json:"id"`
	Kind       string      `json:"kind"`
	Level      string      `json:"level"`
	Path       PursuitPath `json:"path"`
	DurationMs int         `json:"duration_ms"`
	Width      int         `json:"width"`
	Height     int         `json:"height"`
	Prompt     string      `json:"prompt"`
}

const (
	pursuitErrorFloor = 8.0  // mean tracking error (px) below this is superhuman — a computed follow, not a human eye
	pursuitPassMax    = 55.0 // mean error above this = did not track the dot (the gate is not solved)
	pursuitMinSamples = 15   // fewer cursor samples than this over the duration = not a genuine continuous follow
)

// pos evaluates the target position at t milliseconds since the challenge start.
func (p PursuitPath) pos(tMs float64) (x, y float64) {
	t := tMs / 1000.0
	return p.CX + p.A*math.Sin(p.W1*t+p.P1), p.CY + p.B*math.Sin(p.W2*t+p.P2)
}

func pursuitParams(lv Level) (durMs int) {
	switch lv {
	case LevelEasy:
		return 3000
	case LevelHard:
		return 5000
	default:
		return 4000
	}
}

// MintPursuit builds a random Lissajous path + returns the answer (the path + duration, referenced by verify to
// recompute the target position at each cursor sample and score the tracking error).
func MintPursuit(lv Level) (Pursuit, string) {
	const w, h = 300, 200
	path := PursuitPath{
		CX: w / 2.0, CY: h / 2.0, A: 110, B: 70,
		W1: 1.2 + float64(randInt(120))/100.0, // 1.2 - 2.4 rad/s
		W2: 0.8 + float64(randInt(120))/100.0, // 0.8 - 2.0 rad/s (different -> a Lissajous curve, not a line)
		P1: float64(randInt(628)) / 100.0,
		P2: float64(randInt(628)) / 100.0,
	}
	dur := pursuitParams(lv)
	p := Pursuit{
		ID: randHex(16), Kind: "pursuit", Level: string(lv), Path: path, DurationMs: dur, Width: w, Height: h,
		Prompt: "Keep your cursor on the moving dot until it stops.",
	}
	ans, _ := json.Marshal(map[string]any{"path": path, "dur": dur})
	return p, string(ans)
}

// PursuitSample is one cursor reading: t ms since start, and the cursor position.
type PursuitSample struct {
	T float64 `json:"t"`
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// CheckPursuit recomputes the target position at each sample time and returns whether the client tracked (mean
// error below pursuitPassMax with enough samples), the mean tracking error (the superhuman tell), and the count.
func CheckPursuit(expected string, samples []PursuitSample) (pass bool, meanErr float64, n int) {
	var a struct {
		Path PursuitPath `json:"path"`
		Dur  int         `json:"dur"`
	}
	if err := json.Unmarshal([]byte(expected), &a); err != nil {
		return false, 0, 0
	}
	n = len(samples)
	if n < pursuitMinSamples {
		return false, 0, n
	}
	var sum float64
	for _, s := range samples {
		tx, ty := a.Path.pos(s.T)
		sum += math.Hypot(s.X-tx, s.Y-ty)
	}
	meanErr = sum / float64(n)
	return meanErr <= pursuitPassMax, meanErr, n
}
