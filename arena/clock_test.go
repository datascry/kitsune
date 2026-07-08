// arena/clock_test — tests for the analog-clock CAPTCHA gate.
// Covers the PNG render, time-answer normalisation, and the clock-kind verify.

package arena

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestMintClock(t *testing.T) {
	for _, lv := range []Level{LevelEasy, LevelMedium, LevelHard} {
		img, ans := mintClock(lv)
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(img, "data:image/png;base64,"))
		if err != nil || len(raw) < 8 || string(raw[1:4]) != "PNG" {
			t.Errorf("%s: clock image is not a PNG data URI", lv)
		}
		if !strings.Contains(ans, ":") || ans != normClock(ans) {
			t.Errorf("%s: answer %q is not a canonical H:MM time", lv, ans)
		}
	}
}

func TestNormClock(t *testing.T) {
	for in, want := range map[string]string{
		"3:45": "3:45", "03:45": "3:45", "3.45": "3:45", " 3 : 45 ": "3:45", "12:00": "12:00", "garbage": "garbage",
	} {
		if got := normClock(in); got != want {
			t.Errorf("normClock(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCheckCaptchaClock(t *testing.T) {
	if !CheckCaptcha(CaptchaClock, "3:45", "03:45") {
		t.Error("03:45 should match 3:45 (leading-zero normalisation)")
	}
	if !CheckCaptcha(CaptchaClock, "3:45", "3.45") {
		t.Error("dot separator should match")
	}
	if CheckCaptcha(CaptchaClock, "3:45", "3:50") {
		t.Error("wrong time must fail")
	}
}
