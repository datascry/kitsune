// arena/reaction — reaction-time gate: click as soon as the box turns green ("click when ready" anti-bot check).
// NOVEL server-observed tell: the reaction latency (server-clocked = mint->verify age minus the shown delay) below
// the human physiological floor (~150ms simple visual reaction). A bot that clicks the instant the cue fires, or
// ANTICIPATES it (clicks before the go), reacts faster than any human hand-eye loop — impossible by physiology.

package arena

import "strconv"

// Reaction is the PUBLIC challenge — the box turns "go" after DelayMs; the task is reacting to that change, so the
// reaction LATENCY discriminates, not a secret.
type Reaction struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Level   string `json:"level"`
	DelayMs int    `json:"delay_ms"`
	Prompt  string `json:"prompt"`
}

// reactionFloorMs: a reaction latency below this is superhuman. Set under the human simple-visual-reaction floor
// (~150ms; elite ~150-200ms) with margin for network, so it is load-bearing (FP-safe). A negative reaction (a click
// that reaches the server before the go time) is anticipation — also caught by this floor.
const reactionFloorMs = 120

func reactionParams(lv Level) (minD, maxD int) {
	switch lv {
	case LevelEasy:
		return 700, 1400
	case LevelHard:
		return 1200, 3000
	default:
		return 900, 2200
	}
}

// MintReaction picks a random pre-cue delay + returns the answer (the delay, referenced by verify to derive the
// server-observed reaction latency).
func MintReaction(lv Level) (Reaction, string) {
	minD, maxD := reactionParams(lv)
	delay := minD + int(randInt(int64(maxD-minD)))
	r := Reaction{
		ID: randHex(16), Kind: "reaction", Level: string(lv), DelayMs: delay,
		Prompt: "Wait for the box to turn green, then click it as fast as you can.",
	}
	return r, strconv.Itoa(delay)
}

// CheckReaction derives the reaction latency from the SERVER-OBSERVED age (mint->verify) minus the shown delay: a
// human-plausible reaction (>= reactionFloorMs) passes; returns the reaction (negative = clicked before the go).
func CheckReaction(expected string, ageMs int) (pass bool, reaction int) {
	delay, err := strconv.Atoi(expected)
	if err != nil {
		return false, 0
	}
	reaction = ageMs - delay
	return reaction >= reactionFloorMs, reaction
}
