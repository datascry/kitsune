// arena/captcha_test — assert the self-hosted CAPTCHA gates issue, verify a correct answer, and are single-use.
// Covers the primitive (mint/check across families) + the HTTP issue→verify→token flow on the math gate.

package arena

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMintCaptchaAndCheck(t *testing.T) {
	for _, kind := range []CaptchaKind{CaptchaText, CaptchaMath, CaptchaHoneypot} {
		c, answer := MintCaptcha(kind)
		if c.ID == "" || c.Kind != kind {
			t.Fatalf("%s: bad challenge %+v", kind, c)
		}
		if !CheckCaptcha(kind, answer, answer) {
			t.Fatalf("%s: the correct answer was rejected", kind)
		}
		if CheckCaptcha(kind, answer, answer+"x") {
			t.Fatalf("%s: a wrong answer was accepted", kind)
		}
	}
	// text: the answer is rendered as a distorted RASTER PNG (not SVG markup), so it needs OCR — the plaintext
	// answer is not parseable from the challenge (no <text> element; only base64 pixels).
	c, answer := MintCaptcha(CaptchaText)
	if !strings.HasPrefix(c.Image, "data:image/png;base64,") {
		t.Fatalf("text captcha is not a raster PNG: %.40s", c.Image)
	}
	if strings.Contains(c.Image, answer) || strings.Contains(c.Image, "<text") {
		t.Fatal("text captcha leaked the answer / used parseable markup")
	}
	// honeypot: an EMPTY trap field passes; any value fails.
	if !CheckCaptcha(CaptchaHoneypot, "", "") || CheckCaptcha(CaptchaHoneypot, "", "spam") {
		t.Fatal("honeypot check is wrong")
	}
}

func TestCaptchaHTTPFlowMath(t *testing.T) {
	srv := httptest.NewServer(NewMux([]byte("test-secret-32-bytes-long-padxxx")))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/arena/captcha?kind=math")
	if err != nil {
		t.Fatal(err)
	}
	var c Captcha
	_ = json.NewDecoder(resp.Body).Decode(&c)
	resp.Body.Close()
	var a, b int
	if _, err := fmt.Sscanf(c.Prompt, "What is %d + %d?", &a, &b); err != nil {
		t.Fatalf("could not parse math prompt %q: %v", c.Prompt, err)
	}

	verify := func(answer string) map[string]any {
		body, _ := json.Marshal(map[string]any{"kind": "math", "id": c.ID, "answer": answer})
		r, err := http.Post(srv.URL+"/arena/captcha/verify", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(r.Body).Decode(&out)
		return out
	}

	out := verify(fmt.Sprintf("%d", a+b))
	if out["ok"] != true || out["token"] == nil {
		t.Fatalf("a correct math answer did not pass: %v", out)
	}
	// single-use: the id is consumed, so re-verifying (even correctly) fails.
	if verify(fmt.Sprintf("%d", a+b))["ok"] != false {
		t.Fatal("a consumed captcha id was accepted again")
	}
}

func TestCaptchaRejectsWrongAnswer(t *testing.T) {
	srv := httptest.NewServer(NewMux([]byte("test-secret-32-bytes-long-padxxx")))
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/arena/captcha?kind=math")
	var c Captcha
	_ = json.NewDecoder(resp.Body).Decode(&c)
	resp.Body.Close()
	body, _ := json.Marshal(map[string]any{"kind": "math", "id": c.ID, "answer": "-999"})
	r, err := http.Post(srv.URL+"/arena/captcha/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(r.Body).Decode(&out)
	if out["ok"] != false {
		t.Fatalf("a wrong answer was accepted: %v", out)
	}
}

func TestImageSelectAndRotate(t *testing.T) {
	// image-select: the correct index set passes; a wrong set and an empty set fail.
	c, ans := MintCaptcha(CaptchaImageSelect)
	if len(c.Tiles) != 9 || ans == "" {
		t.Fatalf("bad image-select challenge: tiles=%d ans=%q", len(c.Tiles), ans)
	}
	if !CheckCaptcha(CaptchaImageSelect, ans, ans) {
		t.Fatal("correct image-select set rejected")
	}
	if CheckCaptcha(CaptchaImageSelect, ans, "") || CheckCaptcha(CaptchaImageSelect, ans, "99") {
		t.Fatal("wrong/empty image-select set accepted")
	}
	// rotate: upright (0, or within tolerance) passes; far-from-upright fails.
	r, _ := MintCaptcha(CaptchaRotate)
	if r.Image == "" || r.Angle == 0 {
		t.Fatalf("bad rotate challenge: %+v", r)
	}
	for _, ok := range []string{"0", "10", "355"} {
		if !CheckCaptcha(CaptchaRotate, "", ok) {
			t.Fatalf("rotate near-upright %q rejected", ok)
		}
	}
	for _, bad := range []string{"90", "180", "45"} {
		if CheckCaptcha(CaptchaRotate, "", bad) {
			t.Fatalf("rotate off-upright %q accepted", bad)
		}
	}
}
