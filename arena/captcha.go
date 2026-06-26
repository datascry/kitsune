// arena/captcha — self-hosted, GENERIC CAPTCHA gates (text image · math · honeypot), owned infra only.
// Reproduces documented open CAPTCHA MECHANISMS — not a clone of any vendor widget, never a third-party solver.

// These mirror the PoW gates' shape (issue a challenge → the client answers → verify → mint a single-use
// HMAC token), but the "work" is a human-readable test instead of a hash. They are vendor-neutral
// reproductions of the documented families: a distorted-text image (the classic text CAPTCHA, rendered
// server-side as an SVG so the answer never leaves the server in plaintext), a simple arithmetic puzzle, and
// the hidden-honeypot-field trap. The point on the arena is the same as PoW: a client can pass the CAPTCHA
// and STILL be convicted by the detector on coherence — a challenge is not a bot/human discriminator.

package arena

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// CaptchaKind is the self-hosted CAPTCHA family.
type CaptchaKind string

const (
	CaptchaText        CaptchaKind = "text"         // distorted-text image (rasterized PNG — needs OCR)
	CaptchaMath        CaptchaKind = "math"         // simple arithmetic
	CaptchaHoneypot    CaptchaKind = "honeypot"     // hidden trap field that must stay empty
	CaptchaImageSelect CaptchaKind = "image-select" // pick the tiles matching a prompt (reCAPTCHA-v2 category)
)

// : image-select shapes — owned, generic primitives, rendered as rotated raster PNG tiles.
var imageShapes = []string{"circle", "square", "triangle", "star"}

// readable alphabet — excludes the visually ambiguous 0/O/1/I/L so a human can actually read the image.
const captchaAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// the hard alphabet ADDS the confusable glyphs back (0/O, 1/I/L) — harder to OCR, used only at the hard level.
const captchaAlphabetHard = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Captcha is the PUBLIC challenge shown to the client. The answer is NEVER included — it lives only in the
// gate's store (text/math) or is structural (honeypot: the trap field must come back empty).
type Captcha struct {
	Kind   CaptchaKind `json:"kind"`
	ID     string      `json:"id"`              // single-use nonce
	Prompt string      `json:"prompt"`          // human instruction
	Image  string      `json:"image,omitempty"` // text: rasterized PNG (needs OCR); rotate: an SVG arrow
	Field  string      `json:"field,omitempty"` // honeypot: the trap field name that must stay empty to pass
	Tiles  []string    `json:"tiles,omitempty"` // image-select: 9 owned raster PNG tiles (must be classified by CV)
	Angle  int         `json:"angle,omitempty"` // rotate: the initial rotation the user must undo to reach upright
}

// captchaStore holds id -> expected answer for single-use verification (the text/math families need the
// server to remember the answer; honeypot is structural and stores ""). Safe for concurrent use.
type captchaStore struct {
	mu sync.Mutex
	m  map[string]string
}

func newCaptchaStore() *captchaStore { return &captchaStore{m: map[string]string{}} }

func (s *captchaStore) put(id, answer string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = answer
}

// take consumes an id (single-use): returns the stored answer and removes it, so a token cannot be replayed.
func (s *captchaStore) take(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.m[id]
	if ok {
		delete(s.m, id)
	}
	return a, ok
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randInt(maxExclusive int64) int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(maxExclusive))
	if err != nil {
		return 0
	}
	return n.Int64()
}

func randCodeFrom(n int, alphabet string) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(alphabet[randInt(int64(len(alphabet)))])
	}
	return b.String()
}

// mintMath builds an arithmetic prompt + answer scaled by level: easy single-digit addition, medium a small
// +/-/× over 2..12, hard a multiplication of larger operands. Single-operation (no precedence ambiguity).
func mintMath(lv Level) (string, string) {
	switch lv {
	case LevelEasy:
		a, b := randInt(9)+1, randInt(9)+1
		return fmt.Sprintf("What is %d + %d?", a, b), fmt.Sprintf("%d", a+b)
	case LevelHard:
		a, b := randInt(19)+11, randInt(19)+11 // 11..29
		return fmt.Sprintf("What is %d × %d?", a, b), fmt.Sprintf("%d", a*b)
	default:
		a, b := randInt(11)+2, randInt(11)+2 // 2..12
		switch randInt(3) {
		case 0:
			return fmt.Sprintf("What is %d × %d?", a, b), fmt.Sprintf("%d", a*b)
		case 1:
			if a < b {
				a, b = b, a
			}
			return fmt.Sprintf("What is %d - %d?", a, b), fmt.Sprintf("%d", a-b)
		default:
			return fmt.Sprintf("What is %d + %d?", a, b), fmt.Sprintf("%d", a+b)
		}
	}
}

// MintCaptcha builds a fresh challenge of the kind at the given difficulty level and returns it with the
// expected answer (the caller stores the answer for verify; for honeypot the stored answer is "" — it verifies
// structurally). honeypot has no difficulty axis and ignores the level.
func MintCaptcha(kind CaptchaKind, lv Level) (Captcha, string) {
	id := randHex(16)
	switch kind {
	case CaptchaMath:
		prompt, ans := mintMath(lv)
		return Captcha{Kind: CaptchaMath, ID: id, Prompt: prompt}, ans
	case CaptchaHoneypot:
		return Captcha{Kind: CaptchaHoneypot, ID: id, Prompt: "Submit without filling the hidden field.", Field: "website_url"}, ""
	case CaptchaImageSelect:
		k := imageParams(lv)
		target := imageShapes[randInt(int64(len(imageShapes)))]
		tiles := make([]string, k.Tiles)
		var want []int
		for i := range tiles {
			s := imageShapes[randInt(int64(len(imageShapes)))]
			tiles[i] = rasterShape(s, k.Noise) // rotated/noisy PNG — must be CLASSIFIED, not read from markup
			if s == target {
				want = append(want, i)
			}
		}
		if len(want) == 0 { // guarantee at least one target tile
			tiles[0] = rasterShape(target, k.Noise)
			want = []int{0}
		}
		return Captcha{Kind: CaptchaImageSelect, ID: id, Prompt: "Select every " + target + ".", Tiles: tiles}, joinInts(want)
	default:
		k := textParams(lv)
		alphabet := captchaAlphabet
		if k.Confusable {
			alphabet = captchaAlphabetHard
		}
		code := randCodeFrom(k.Length, alphabet)
		// Rendered as a DISTORTED RASTER PNG (not SVG): the answer is in the pixels, not the markup, so a
		// browserless parser can no longer read it — solving the text gate now needs real OCR. See raster.go.
		return Captcha{Kind: CaptchaText, ID: id, Prompt: "Type the characters in the image.", Image: rasterText(code, k)}, strings.ToUpper(code)
	}
}

func joinInts(xs []int) string {
	sort.Ints(xs)
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, ",")
}

// normIndexSet sorts + dedupes a comma-separated index list into a canonical form for set comparison.
func normIndexSet(s string) string {
	seen := map[int]bool{}
	var xs []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || seen[n] {
			continue
		}
		seen[n] = true
		xs = append(xs, n)
	}
	return joinInts(xs)
}

// CheckCaptcha reports whether submitted answers the challenge: case-insensitive exact match for text/math;
// for honeypot the submitted trap-field value must be EMPTY (a bot that fills every field fails).
func CheckCaptcha(kind CaptchaKind, expected, submitted string) bool {
	switch kind {
	case CaptchaHoneypot:
		return strings.TrimSpace(submitted) == ""
	case CaptchaImageSelect:
		return normIndexSet(expected) == normIndexSet(submitted) && normIndexSet(submitted) != ""
	default:
		return strings.EqualFold(strings.TrimSpace(submitted), strings.TrimSpace(expected))
	}
}

// SignCaptchaToken mints the HMAC pass token for a solved CAPTCHA (verifiable only by the issuing gate).
func SignCaptchaToken(secret []byte, kind CaptchaKind, id string) string {
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "captcha:%s:%s", kind, id)
	return hex.EncodeToString(mac.Sum(nil))
}
