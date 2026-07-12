// arena/count_test — tests for the counting gate: mint shape + answer, and the guess-matching logic.
// Confirms the answer is in range, a correct guess passes, a wrong guess fails, and the guess parser is tolerant.

package arena

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMintCount(t *testing.T) {
	for _, lv := range []Level{LevelEasy, LevelMedium, LevelHard} {
		c, ans := MintCount(lv)
		m := countParams(lv)
		if c.Kind != "count" || c.ID == "" || !strings.HasPrefix(c.Image, "data:image/png;base64,") {
			t.Fatalf("%s: bad shape %+v", lv, c.Kind)
		}
		var a struct{ Answer, Total int }
		if err := json.Unmarshal([]byte(ans), &a); err != nil || a.Total != m || a.Answer < 1 || a.Answer > m {
			t.Fatalf("%s: answer %+v out of range for total %d", lv, a, m)
		}
	}
}

func TestCheckCount(t *testing.T) {
	_, ans := MintCount(LevelMedium)
	var a struct{ Answer, Total int }
	_ = json.Unmarshal([]byte(ans), &a)

	if pass, total := CheckCount(ans, a.Answer); !pass || total != a.Total {
		t.Errorf("correct guess: pass=%v total=%v (want pass, total %d)", pass, total, a.Total)
	}
	if pass, _ := CheckCount(ans, a.Answer+1); pass {
		t.Error("a wrong guess must fail")
	}
	if pass, _ := CheckCount("", a.Answer); pass {
		t.Error("empty target must fail")
	}
	if parseCountGuess("7") != 7 || parseCountGuess("nope") != -1 {
		t.Error("parseCountGuess mismatch")
	}
}
