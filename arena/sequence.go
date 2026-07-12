// arena/sequence — ordered click-in-sequence gate: click N numbered tiles in order (GeeTest icon-order / NetEase
// Yidun family). NOVEL server-observed tell: solving faster than a human can visually locate + click N ordered
// targets (age < N * a per-target floor), OR a metronomic inter-click cadence (a fixed-delay clicker, std ~ 0).

package arena

import (
	"encoding/json"
	"math"
)

// SeqTile is one numbered target at a shuffled position — the client clicks the tiles in numeric order.
type SeqTile struct {
	ID int `json:"id"`
	X  int `json:"x"`
	Y  int `json:"y"`
}

// Sequence is the PUBLIC challenge — the order (numeric) is shown; the task is the ordered CLICKING, not guessing a
// secret (the arena thesis: the solve-behaviour discriminates, not the puzzle).
type Sequence struct {
	ID     string    `json:"id"`
	Kind   string    `json:"kind"`
	Level  string    `json:"level"`
	Tiles  []SeqTile `json:"tiles"`
	Prompt string    `json:"prompt"`
}

// seqPerTargetMs: the minimum a human needs to visually locate the next numbered tile and click it (saccade + move
// + click). A whole solve (age) under N * this is superhuman — the load-bearing, FP-safe prong.
const seqPerTargetMs = 250

// seqCadenceFloorMs: inter-click interval std below this (with >= 3 clicks) is a metronomic fixed-delay clicker; a
// human's inter-click gaps vary. Corroborating prong (only judged when per-click times were reported).
const seqCadenceFloorMs = 15.0

func seqParams(lv Level) (n int) {
	switch lv {
	case LevelEasy:
		return 3
	case LevelHard:
		return 5
	default:
		return 4
	}
}

// MintSequence places N numbered tiles at shuffled positions + returns the answer (the correct click order 1..N).
func MintSequence(lv Level) (Sequence, string) {
	n := seqParams(lv)
	tiles := make([]SeqTile, n)
	for i := range tiles {
		tiles[i] = SeqTile{ID: i + 1, X: 20 + int(randInt(280)), Y: 20 + int(randInt(180))}
	}
	// shuffle the SLICE so the numeric labels are not laid out in positional order (a real visual search each step)
	for i := len(tiles) - 1; i > 0; i-- {
		j := int(randInt(int64(i + 1)))
		tiles[i], tiles[j] = tiles[j], tiles[i]
	}
	order := make([]int, n)
	for i := range order {
		order[i] = i + 1 // the correct click order is ascending numeric
	}
	s := Sequence{
		ID: randHex(16), Kind: "sequence", Level: string(lv), Tiles: tiles,
		Prompt: "Click the tiles in numeric order: 1, 2, 3, …",
	}
	b, _ := json.Marshal(order)
	return s, string(b)
}

// CheckSequence reports whether the clicks match the reference order exactly, the tile count, and the inter-click
// cadence std (the metronomic tell) from the click timestamps. Wrong count/order => pass=false.
func CheckSequence(expected string, clicks []int, times []int) (pass bool, n int, cadenceStd float64) {
	var order []int
	if err := json.Unmarshal([]byte(expected), &order); err != nil || len(order) == 0 {
		return false, 0, 0
	}
	n = len(order)
	if len(clicks) != n {
		return false, n, 0
	}
	pass = true
	for i := range order {
		if clicks[i] != order[i] {
			pass = false
		}
	}
	if len(times) == n && n >= 3 {
		gaps := make([]float64, n-1)
		for i := 1; i < n; i++ {
			gaps[i-1] = float64(times[i] - times[i-1])
		}
		var mean float64
		for _, g := range gaps {
			mean += g
		}
		mean /= float64(len(gaps))
		var v float64
		for _, g := range gaps {
			v += (g - mean) * (g - mean)
		}
		cadenceStd = math.Sqrt(v / float64(len(gaps)))
	}
	return pass, n, cadenceStd
}
