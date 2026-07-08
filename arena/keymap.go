// arena/keymap — broken/remapped-keyboard gate: the keys silently produce other characters; type the target.
// NOVEL server-observed tell: a correct answer with ZERO exploration (no backspaces/corrections) means the client
// decoded the remap from the payload and typed it directly — a human must PROBE the hidden mapping, so it corrects.

package arena

import (
	"encoding/json"
	"strings"
)

// keymapCharset: the key/output alphabet (no 0/O, 1/I/L confusables — a human read of the output stays unambiguous).
const keymapCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// Keymap is the PUBLIC challenge. Remap IS sent (the page applies it client-side so a keypress shows the remapped
// char) — that is the point: a bot that READS it types the answer with no exploration and is convicted.
type Keymap struct {
	ID     string            `json:"id"`
	Kind   string            `json:"kind"`
	Level  string            `json:"level"`
	Target string            `json:"target"`
	Remap  map[string]string `json:"remap"` // physical key -> the character it actually produces
	Prompt string            `json:"prompt"`
}

func keymapParams(lv Level) (targetLen, remapSize int) {
	switch lv {
	case LevelEasy:
		return 4, 12
	case LevelHard:
		return 6, 26
	default:
		return 5, 18
	}
}

// keymapShuffle returns a Fisher-Yates shuffle of s's bytes (using the arena's crypto randInt).
func keymapShuffle(s string) []byte {
	b := []byte(s)
	for i := len(b) - 1; i > 0; i-- {
		j := int(randInt(int64(i + 1)))
		b[i], b[j] = b[j], b[i]
	}
	return b
}

// MintKeymap builds a remap (a bijection over remapSize keys) + a target drawn from the outputs, so every target
// char is typeable. The answer is "target|remapJSON" (the verify replays the key trace through the remap).
func MintKeymap(lv Level) (Keymap, string) {
	tlen, rsize := keymapParams(lv)
	keys := keymapShuffle(keymapCharset)[:rsize] // rsize distinct key chars
	outs := keymapShuffle(string(keys))          // the outputs = a permutation of the keys -> a bijection
	remap := make(map[string]string, rsize)
	for i := range keys {
		remap[string(keys[i])] = string(outs[i])
	}
	target := make([]byte, tlen)
	for i := range target {
		target[i] = outs[int(randInt(int64(len(outs))))]
	}
	km := Keymap{
		ID: randHex(16), Kind: "keymap", Level: string(lv), Target: string(target), Remap: remap,
		Prompt: "Type the target — but the keys are remapped. Discover the mapping by trying keys, then type it.",
	}
	rj, _ := json.Marshal(remap)
	return km, string(target) + "|" + string(rj)
}

// keymapFloorMs is a conservative lower bound on DISCOVERING the hidden remap by probing + typing the target: no
// human finds which key produces each of the target chars and types them faster than this (the server-observed
// second prong, complementing the zero-backspaces exploration tell).
func keymapFloorMs(expected string) int {
	target, _, _ := strings.Cut(expected, "|")
	return len(target) * 600
}

// CheckKeymap replays the key trace (each element a key char or the literal "BACK") through the remap and reports
// whether the resulting buffer equals the target, plus the keystroke + backspace counts (the exploration signal).
func CheckKeymap(expected string, trace []string) (pass bool, keystrokes, backspaces int) {
	target, remapJSON, ok := strings.Cut(expected, "|")
	if !ok {
		return false, 0, 0
	}
	var remap map[string]string
	if json.Unmarshal([]byte(remapJSON), &remap) != nil {
		return false, 0, 0
	}
	var buf []byte
	for _, k := range trace {
		if k == "BACK" {
			backspaces++
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
			}
			continue
		}
		keystrokes++
		if out, mapped := remap[k]; mapped && len(out) == 1 {
			buf = append(buf, out[0])
		}
		// an unmapped key (a probe of a key not on the board) produces nothing but still counts as a keystroke
	}
	return string(buf) == target, keystrokes, backspaces
}
