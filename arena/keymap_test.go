// arena/keymap_test — tests for the remapped-keyboard gate: mint bijection/typeability + trace replay semantics.
// Confirms a decoded bot solve has zero backspaces while a human that probes-then-corrects has backspaces > 0.

package arena

import (
	"strings"
	"testing"
)

func TestMintKeymap(t *testing.T) {
	for _, lv := range []Level{LevelEasy, LevelMedium, LevelHard} {
		km, ans := MintKeymap(lv)
		tlen, rsize := keymapParams(lv)
		if km.Kind != "keymap" || km.ID == "" || len(km.Target) != tlen || len(km.Remap) != rsize {
			t.Fatalf("%s: bad shape target=%q remap=%d", lv, km.Target, len(km.Remap))
		}
		outs := map[string]bool{}
		for _, v := range km.Remap {
			outs[v] = true
		}
		if len(outs) != rsize {
			t.Errorf("%s: remap not a bijection (%d distinct outputs, want %d)", lv, len(outs), rsize)
		}
		for i := 0; i < len(km.Target); i++ {
			if !outs[km.Target[i:i+1]] {
				t.Errorf("%s: target char %q is not typeable via the remap", lv, km.Target[i:i+1])
			}
		}
		if !strings.HasPrefix(ans, km.Target+"|") {
			t.Errorf("%s: answer must encode target|remap", lv)
		}
	}
}

func TestCheckKeymap(t *testing.T) {
	km, ans := MintKeymap(LevelMedium)
	inv := map[string]string{} // output char -> the key that produces it
	for k, v := range km.Remap {
		inv[v] = k
	}

	// BOT: type the decoded keys directly — pass with ZERO exploration
	var bot []string
	for i := 0; i < len(km.Target); i++ {
		bot = append(bot, inv[km.Target[i:i+1]])
	}
	if pass, ks, bs := CheckKeymap(ans, bot); !pass || bs != 0 || ks != len(km.Target) {
		t.Errorf("decoded bot: pass=%v keystrokes=%d backspaces=%d (want pass, bs 0, ks %d)", pass, ks, bs, len(km.Target))
	}

	// HUMAN: probe a wrong key, backspace, then type correctly -> pass with backspaces > 0
	wrongKey := ""
	for k, v := range km.Remap {
		if v != km.Target[:1] {
			wrongKey = k
			break
		}
	}
	human := []string{wrongKey, "BACK"}
	for i := 0; i < len(km.Target); i++ {
		human = append(human, inv[km.Target[i:i+1]])
	}
	if pass, _, bs := CheckKeymap(ans, human); !pass || bs == 0 {
		t.Errorf("human probe: pass=%v backspaces=%d (want pass, bs > 0)", pass, bs)
	}

	// a single wrong key must not pass
	if pass, _, _ := CheckKeymap(ans, []string{wrongKey}); pass {
		t.Error("a single wrong key must not pass")
	}
}
