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
	"html"
	"math/big"
	"strings"
	"sync"
)

// CaptchaKind is the self-hosted CAPTCHA family.
type CaptchaKind string

const (
	CaptchaText     CaptchaKind = "text"     // distorted-text image (server-rendered SVG)
	CaptchaMath     CaptchaKind = "math"     // simple arithmetic
	CaptchaHoneypot CaptchaKind = "honeypot" // hidden trap field that must stay empty
)

// readable alphabet — excludes the visually ambiguous 0/O/1/I/L so a human can actually read the image.
const captchaAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// Captcha is the PUBLIC challenge shown to the client. The answer is NEVER included — it lives only in the
// gate's store (text/math) or is structural (honeypot: the trap field must come back empty).
type Captcha struct {
	Kind   CaptchaKind `json:"kind"`
	ID     string      `json:"id"`              // single-use nonce
	Prompt string      `json:"prompt"`          // human instruction
	Image  string      `json:"image,omitempty"` // text: a data: SVG of the distorted code (answer not in plaintext)
	Field  string      `json:"field,omitempty"` // honeypot: the trap field name that must stay empty to pass
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

// svgFor renders code as a small distorted-text SVG (per-char rotation + jitter + a couple of noise strokes),
// returned as a data: URI. The plaintext code is NOT in the document the client receives — only this image is.
func svgFor(code string) string {
	var g strings.Builder
	for i, ch := range code {
		x := 14 + i*22
		y := 26 + int(randInt(9)) - 4
		rot := int(randInt(31)) - 15
		fmt.Fprintf(&g, `<text x="%d" y="%d" transform="rotate(%d %d %d)" font-family="monospace" font-size="26" fill="#444">%s</text>`,
			x, y, rot, x, y, html.EscapeString(string(ch)))
	}
	for i := 0; i < 3; i++ {
		fmt.Fprintf(&g, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#999" stroke-width="1"/>`,
			randInt(140), randInt(40), randInt(140), randInt(40))
	}
	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="40" role="img" aria-label="text challenge">%s</svg>`,
		14+len(code)*22, g.String())
	return "data:image/svg+xml;utf8," + strings.NewReplacer("#", "%23", "\n", "").Replace(svg)
}

// MintCaptcha builds a fresh challenge of the kind and returns it with the expected answer (the caller stores
// the answer for verify; for honeypot the answer is "" — the trap field must come back empty).
func MintCaptcha(kind CaptchaKind) (Captcha, string) {
	id := randHex(16)
	switch kind {
	case CaptchaMath:
		a, b := randInt(9)+1, randInt(9)+1
		return Captcha{Kind: CaptchaMath, ID: id, Prompt: fmt.Sprintf("What is %d + %d?", a, b)}, fmt.Sprintf("%d", a+b)
	case CaptchaHoneypot:
		return Captcha{Kind: CaptchaHoneypot, ID: id, Prompt: "Submit without filling the hidden field.", Field: "website_url"}, ""
	default:
		code := randCode(5)
		return Captcha{Kind: CaptchaText, ID: id, Prompt: "Type the characters in the image.", Image: svgFor(code)}, strings.ToUpper(code)
	}
}

// CheckCaptcha reports whether submitted answers the challenge: case-insensitive exact match for text/math;
// for honeypot the submitted trap-field value must be EMPTY (a bot that fills every field fails).
func CheckCaptcha(kind CaptchaKind, expected, submitted string) bool {
	if kind == CaptchaHoneypot {
		return strings.TrimSpace(submitted) == ""
	}
	return strings.EqualFold(strings.TrimSpace(submitted), strings.TrimSpace(expected))
}

// SignCaptchaToken mints the HMAC pass token for a solved CAPTCHA (verifiable only by the issuing gate).
func SignCaptchaToken(secret []byte, kind CaptchaKind, id string) string {
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "captcha:%s:%s", kind, id)
	return hex.EncodeToString(mac.Sum(nil))
}
