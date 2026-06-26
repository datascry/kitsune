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
	"math"
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
	CaptchaRotate      CaptchaKind = "rotate"       // rotate an object upright (Arkose/FunCaptcha category)
)

// : rotate: how close (degrees) to upright counts as solved.
const rotateTolDeg = 18

// : image-select shapes — owned, generic primitives, rendered as rotated raster PNG tiles.
var imageShapes = []string{"circle", "square", "triangle", "star"}

// readable alphabet — excludes the visually ambiguous 0/O/1/I/L so a human can actually read the image.
const captchaAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

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

func randCode(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(captchaAlphabet[randInt(int64(len(captchaAlphabet)))])
	}
	return b.String()
}

// arrowSVG renders an upright arrow (pointing up); the page rotates it by the challenge's initial angle, and
// the human rotates it back to upright.
func arrowSVG() string {
	svg := `<svg xmlns="http://www.w3.org/2000/svg" width="90" height="90"><polygon points="45,10 70,55 50,55 50,80 40,80 40,55 20,55" fill="#7a5cff"/></svg>`
	return "data:image/svg+xml;utf8," + strings.NewReplacer("#", "%23").Replace(svg)
}

// MintCaptcha builds a fresh challenge of the kind and returns it with the expected answer (the caller stores
// the answer for verify; for honeypot/rotate the stored answer is "" — those verify structurally).
func MintCaptcha(kind CaptchaKind) (Captcha, string) {
	id := randHex(16)
	switch kind {
	case CaptchaMath:
		a, b := randInt(9)+1, randInt(9)+1
		return Captcha{Kind: CaptchaMath, ID: id, Prompt: fmt.Sprintf("What is %d + %d?", a, b)}, fmt.Sprintf("%d", a+b)
	case CaptchaHoneypot:
		return Captcha{Kind: CaptchaHoneypot, ID: id, Prompt: "Submit without filling the hidden field.", Field: "website_url"}, ""
	case CaptchaImageSelect:
		target := imageShapes[randInt(int64(len(imageShapes)))]
		tiles := make([]string, 9)
		var want []int
		for i := range tiles {
			s := imageShapes[randInt(int64(len(imageShapes)))]
			tiles[i] = rasterShape(s) // rotated/noisy PNG — must be CLASSIFIED, not read from markup
			if s == target {
				want = append(want, i)
			}
		}
		if len(want) == 0 { // guarantee at least one target tile
			tiles[0] = rasterShape(target)
			want = []int{0}
		}
		return Captcha{Kind: CaptchaImageSelect, ID: id, Prompt: "Select every " + target + ".", Tiles: tiles}, joinInts(want)
	case CaptchaRotate:
		angle := 40 + int(randInt(281)) // 40..320° off upright (well outside the solve tolerance)
		return Captcha{Kind: CaptchaRotate, ID: id, Prompt: "Rotate the arrow to point straight up.", Image: arrowSVG(), Angle: angle}, ""
	default:
		code := randCode(5)
		// Rendered as a DISTORTED RASTER PNG (not SVG): the answer is in the pixels, not the markup, so a
		// browserless parser can no longer read it — solving the text gate now needs real OCR. See raster.go.
		return Captcha{Kind: CaptchaText, ID: id, Prompt: "Type the characters in the image.", Image: rasterText(code)}, strings.ToUpper(code)
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
	case CaptchaRotate:
		// submitted is the FINAL displayed angle; pass when it is within tolerance of upright (0° mod 360).
		f, err := strconv.ParseFloat(strings.TrimSpace(submitted), 64)
		if err != nil {
			return false
		}
		d := math.Mod(math.Abs(f), 360)
		if d > 180 {
			d = 360 - d
		}
		return d <= rotateTolDeg
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
