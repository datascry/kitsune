// arena/audio_test — tests for the spoken-digit audio gate mint/verify + the pure-Go WAV codec.
// Covers corpus load, mint answer/clip validity, verify accept/reject, and a WAV encode/decode roundtrip.

package arena

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestAudioCorpusLoaded(t *testing.T) {
	for d := 0; d < 10; d++ {
		if len(digitSamples[d]) == 0 {
			t.Errorf("no embedded FSDD samples for digit %d", d)
		}
	}
}

func TestMintAudioProducesClipAndAnswer(t *testing.T) {
	for _, lv := range []Level{LevelEasy, LevelMedium, LevelHard} {
		a, ans := MintAudio(lv)
		if len(ans) != audioSeqLen(lv) || digitsOnly(ans) != ans {
			t.Errorf("%s: bad answer %q (want %d digits)", lv, ans, audioSeqLen(lv))
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(a.Clip, "data:audio/wav;base64,"))
		if err != nil || len(decodeWAV(raw)) == 0 {
			t.Errorf("%s: clip is not a decodable non-empty WAV (err=%v)", lv, err)
		}
		if a.Kind != "audio" || a.ID == "" {
			t.Errorf("%s: bad challenge metadata %+v", lv, a)
		}
	}
}

func TestCheckAudio(t *testing.T) {
	cases := []struct {
		expected, submitted string
		want                bool
	}{
		{"1234", "1234", true},
		{"1234", "1 2 3 4", true}, // digits-only normalisation
		{"1234", "1235", false},
		{"1234", "", false},
		{"", "", false}, // no answer stored => never passes
	}
	for _, c := range cases {
		if CheckAudio(c.expected, c.submitted) != c.want {
			t.Errorf("CheckAudio(%q,%q)=%v want %v", c.expected, c.submitted, !c.want, c.want)
		}
	}
}

func TestWAVRoundtrip(t *testing.T) {
	in := []int16{0, 100, -100, 32767, -32768, 5}
	out := decodeWAV(encodeWAV(in, 8000))
	if len(out) != len(in) {
		t.Fatalf("roundtrip len %d != %d", len(out), len(in))
	}
	for i := range in {
		if out[i] != in[i] {
			t.Errorf("sample %d: %d != %d", i, out[i], in[i])
		}
	}
}
