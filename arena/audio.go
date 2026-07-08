// arena/audio — spoken-digit audio CAPTCHA: the ASR-benchmark twin of the text (OCR) + image (CV) gates.
// Mints a random digit sequence from an embedded CC-BY-SA FSDD subset, concatenated + distorted per level.

package arena

import (
	"embed"
	"encoding/base64"
	"encoding/binary"
	"io/fs"
	"math"
	"strings"
)

//go:embed assets/fsdd/*.wav
var fsddFS embed.FS

const audioSampleRate = 8000

// digitSamples[d] is the set of PCM sample-slices for spoken digit d (0..9), loaded once from the embedded corpus.
var digitSamples = loadDigitSamples()

func loadDigitSamples() [10][][]int16 {
	var out [10][][]int16
	entries, _ := fs.ReadDir(fsddFS, "assets/fsdd")
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".wav") || name[0] < '0' || name[0] > '9' {
			continue
		}
		b, err := fsddFS.ReadFile("assets/fsdd/" + name)
		if err != nil {
			continue
		}
		if pcm := decodeWAV(b); pcm != nil {
			d := name[0] - '0'
			out[d] = append(out[d], pcm)
		}
	}
	return out
}

// Audio is the public challenge shown to the client — the answer is NEVER included; it lives only in the store.
type Audio struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Level  string `json:"level"`
	Prompt string `json:"prompt"`
	Clip   string `json:"clip"` // data:audio/wav;base64,... — an <audio> source
	Digits int    `json:"digits"`
}

func audioSeqLen(lv Level) int {
	switch lv {
	case LevelEasy:
		return 4
	case LevelHard:
		return 6
	default:
		return 5
	}
}

// audioGap is the silence (samples) between spoken digits — it shrinks with difficulty so the clips bleed together.
func audioGap(lv Level) int {
	switch lv {
	case LevelEasy:
		return audioSampleRate / 4 // 250 ms
	case LevelHard:
		return audioSampleRate / 20 // 50 ms
	default:
		return audioSampleRate / 8 // 125 ms
	}
}

// MintAudio builds a spoken-digit clip + its answer (the digit string). The caller stores the answer for verify.
func MintAudio(lv Level) (Audio, string) {
	n := audioSeqLen(lv)
	var digits strings.Builder
	var samples []int16
	for i := 0; i < n; i++ {
		d := randInt(10)
		digits.WriteByte(byte('0') + byte(d))
		if set := digitSamples[d]; len(set) > 0 {
			samples = append(samples, set[randInt(int64(len(set)))]...)
		}
		samples = append(samples, make([]int16, audioGap(lv))...)
	}
	distortAudio(samples, lv)
	wav := encodeWAV(samples, audioSampleRate)
	return Audio{
		ID:     randHex(16),
		Kind:   "audio",
		Level:  string(lv),
		Prompt: "Type the digits you hear.",
		Clip:   "data:audio/wav;base64," + base64.StdEncoding.EncodeToString(wav),
		Digits: n,
	}, digits.String()
}

// distortAudio adds per-level additive noise + a faint background tone — the audio analog of the image gates'
// sine-warp + speckle. In place. FP-safe: a human still hears the digits; it only costs an ASR model accuracy.
func distortAudio(s []int16, lv Level) {
	var noiseAmp, tone float64
	switch lv {
	case LevelEasy:
		noiseAmp = 400
	case LevelHard:
		noiseAmp, tone = 1800, 600
	default:
		noiseAmp, tone = 900, 250
	}
	for i := range s {
		v := float64(s[i])
		v += (float64(randInt(2001)) - 1000) / 1000.0 * noiseAmp
		if tone > 0 {
			v += tone * math.Sin(2*math.Pi*180*float64(i)/audioSampleRate)
		}
		s[i] = clampInt16(v)
	}
}

func clampInt16(v float64) int16 {
	if v > 32767 {
		return 32767
	}
	if v < -32768 {
		return -32768
	}
	return int16(v)
}

// CheckAudio reports whether a submitted transcription matches: its digits (punctuation/space-stripped) must equal
// the expected digit string exactly.
func CheckAudio(expected, submitted string) bool {
	return expected != "" && digitsOnly(submitted) == expected
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// --- pure-Go WAV codec (8 kHz mono 16-bit PCM — no runtime deps, the distroless-runtime constraint) ---

func decodeWAV(b []byte) []int16 {
	if len(b) < 44 || string(b[0:4]) != "RIFF" || string(b[8:12]) != "WAVE" {
		return nil
	}
	i := 12
	for i+8 <= len(b) {
		id := string(b[i : i+4])
		size := int(binary.LittleEndian.Uint32(b[i+4 : i+8]))
		i += 8
		if id == "data" {
			if i+size > len(b) {
				size = len(b) - i
			}
			n := size / 2
			out := make([]int16, n)
			for k := 0; k < n; k++ {
				out[k] = int16(binary.LittleEndian.Uint16(b[i+2*k : i+2*k+2]))
			}
			return out
		}
		i += size
		if size%2 == 1 {
			i++ // chunks are word-aligned
		}
	}
	return nil
}

func encodeWAV(samples []int16, rate int) []byte {
	dataLen := len(samples) * 2
	buf := make([]byte, 44+dataLen)
	copy(buf[0:4], "RIFF")
	binary.LittleEndian.PutUint32(buf[4:8], uint32(36+dataLen))
	copy(buf[8:12], "WAVE")
	copy(buf[12:16], "fmt ")
	binary.LittleEndian.PutUint32(buf[16:20], 16)
	binary.LittleEndian.PutUint16(buf[20:22], 1) // PCM
	binary.LittleEndian.PutUint16(buf[22:24], 1) // mono
	binary.LittleEndian.PutUint32(buf[24:28], uint32(rate))
	binary.LittleEndian.PutUint32(buf[28:32], uint32(rate*2))
	binary.LittleEndian.PutUint16(buf[32:34], 2)
	binary.LittleEndian.PutUint16(buf[34:36], 16)
	copy(buf[36:40], "data")
	binary.LittleEndian.PutUint32(buf[40:44], uint32(dataLen))
	for k, s := range samples {
		binary.LittleEndian.PutUint16(buf[44+2*k:], uint16(s))
	}
	return buf
}
