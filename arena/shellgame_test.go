// arena/shellgame_test — tests for the shell-game gate: shuffle validity, answer tracking, and verify semantics.
// Independently replays the swaps to confirm the minted answer is the true final ball position.

package arena

import (
	"strconv"
	"strings"
	"testing"
)

func TestMintShellTracksBall(t *testing.T) {
	for _, lv := range []Level{LevelEasy, LevelMedium, LevelHard} {
		s, ans := MintShell(lv)
		cups, nswaps, _ := shellParams(lv)
		if s.Cups != cups || len(s.Swaps) != nswaps || s.ShuffleMs <= 0 {
			t.Fatalf("%s: bad shape cups=%d swaps=%d ms=%d", lv, s.Cups, len(s.Swaps), s.ShuffleMs)
		}
		// independently replay the swaps from Start — the result must equal the minted answer position
		ball := s.Start
		total := 0
		for _, sw := range s.Swaps {
			if sw.A < 0 || sw.A >= cups || sw.B < 0 || sw.B >= cups || sw.A == sw.B {
				t.Fatalf("%s: invalid swap %+v", lv, sw)
			}
			if ball == sw.A {
				ball = sw.B
			} else if ball == sw.B {
				ball = sw.A
			}
			total += sw.Ms
		}
		pos, ms, _ := strings.Cut(ans, ":")
		if pos != strconv.Itoa(ball) {
			t.Errorf("%s: answer pos %s != replayed ball %d", lv, pos, ball)
		}
		if ms != strconv.Itoa(total) || shellFloorMs(ans) != total {
			t.Errorf("%s: answer ms %s != shuffle total %d", lv, ms, total)
		}
	}
}

func TestCheckShell(t *testing.T) {
	if !CheckShell("2:2080", "2") {
		t.Error("correct cup should pass")
	}
	if CheckShell("2:2080", "1") {
		t.Error("wrong cup must fail")
	}
	if CheckShell("2:2080", "2080") {
		t.Error("must compare the position, not the floor ms")
	}
	if CheckShell("", "2") {
		t.Error("empty answer must fail")
	}
}
