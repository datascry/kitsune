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
	// text: the answer is rendered as an SVG image and is NOT exposed in plaintext on the public challenge.
	c, answer := MintCaptcha(CaptchaText)
	if !strings.Contains(c.Image, "svg") {
		t.Fatal("text captcha did not render an SVG image")
	}
	if strings.Contains(c.Image, answer) {
		t.Fatal("text captcha leaked the plaintext answer into the image markup")
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
