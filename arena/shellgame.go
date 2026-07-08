// arena/shellgame — shell-game gate (track-under-occlusion, anti-LLM): a ball hidden under one of N cups.
// A server-defined swap sequence shuffles it; the client clicks the final cup. NOVEL server-observed tell: a
// correct answer submitted FASTER than the shuffle runtime was precomputed from the swap payload, not watched.

package arena

import (
	"fmt"
	"strconv"
	"strings"
)

// ShellSwap is one animated swap of two cup positions (Ms = its animation duration).
type ShellSwap struct {
	A  int `json:"a"`
	B  int `json:"b"`
	Ms int `json:"ms"`
}

// Shell is the PUBLIC challenge — the final ball position (the answer) is NEVER included.
type Shell struct {
	ID        string      `json:"id"`
	Kind      string      `json:"kind"`
	Level     string      `json:"level"`
	Cups      int         `json:"cups"`
	Start     int         `json:"start"` // initial ball cup, shown before the shuffle starts
	Swaps     []ShellSwap `json:"swaps"`
	ShuffleMs int         `json:"shuffle_ms"` // total shuffle runtime = the human watch floor
	Prompt    string      `json:"prompt"`
}

func shellParams(lv Level) (cups, swaps, swapMs int) {
	switch lv {
	case LevelEasy:
		return 3, 5, 420
	case LevelHard:
		return 5, 12, 160
	default:
		return 3, 8, 260
	}
}

// MintShell builds a shuffle + returns the answer encoded as "finalPos:shuffleMs" (the position is what the client
// must click; the ms is the watch-floor the verify uses to flag a precomputed answer).
func MintShell(lv Level) (Shell, string) {
	cups, nswaps, swapMs := shellParams(lv)
	start := int(randInt(int64(cups)))
	ball := start
	swaps := make([]ShellSwap, nswaps)
	total := 0
	for i := 0; i < nswaps; i++ {
		a := int(randInt(int64(cups)))
		b := int(randInt(int64(cups - 1)))
		if b >= a { // pick b != a uniformly
			b++
		}
		swaps[i] = ShellSwap{A: a, B: b, Ms: swapMs}
		total += swapMs
		if ball == a {
			ball = b
		} else if ball == b {
			ball = a
		}
	}
	s := Shell{
		ID: randHex(16), Kind: "shell", Level: string(lv), Cups: cups, Start: start,
		Swaps: swaps, ShuffleMs: total,
		Prompt: "Watch the shuffle, then click the cup hiding the ball.",
	}
	return s, fmt.Sprintf("%d:%d", ball, total)
}

// CheckShell reports whether the submitted cup index matches the final ball position (the part before the ":").
func CheckShell(expected, submitted string) bool {
	pos, _, ok := strings.Cut(expected, ":")
	return ok && strings.TrimSpace(submitted) == pos
}

// shellFloorMs is the shuffle runtime encoded in the stored answer — the human watch-floor for the verify.
func shellFloorMs(expected string) int {
	if _, ms, ok := strings.Cut(expected, ":"); ok {
		if v, err := strconv.Atoi(ms); err == nil {
			return v
		}
	}
	return 0
}
