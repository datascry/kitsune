// edge/proxy/reverseproxy_test — tests for per-request fingerprint decoration (prepare).
// Covers session minting vs cookie reuse, signal emission, nil hello, and id-mint failure.

package proxy

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
	"github.com/datascry/kitsune/edge/internal/session"
)

func helloFixture(t *testing.T) *fingerprint.ClientHello {
	t.Helper()
	ch, err := fingerprint.ParseClientHello(minimalClientHello())
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func req(t *testing.T, cookie string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://localhost/", nil)
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: session.CookieName, Value: cookie})
	}
	return r
}

func TestPrepareMintsSession(t *testing.T) {
	prep, err := prepare(req(t, ""), helloFixture(t), nil, fingerprint.HintTable{}, fixedID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if prep.sessionID != "fixed-session" || prep.setCookie == nil {
		t.Errorf("session=%s setCookie=%v", prep.sessionID, prep.setCookie)
	}
	if len(prep.signals) != 3 {
		t.Errorf("want ja3+ja4+observed_ip signals, got %d", len(prep.signals))
	}
	if last := prep.signals[len(prep.signals)-1]; last.Kind != "observed_ip" {
		t.Errorf("expected a trailing observed_ip signal, got kind=%s", last.Kind)
	}
}

func TestPrepareReusesCookie(t *testing.T) {
	prep, err := prepare(req(t, "abc"), helloFixture(t), nil, fingerprint.HintTable{}, fixedID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if prep.sessionID != "abc" || prep.setCookie != nil {
		t.Errorf("session=%s setCookie=%v", prep.sessionID, prep.setCookie)
	}
}

func TestPrepareNilHello(t *testing.T) {
	prep, err := prepare(req(t, "abc"), nil, nil, fingerprint.HintTable{}, fixedID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// No ClientHello → no ja3/ja4, but the observed source IP is still captured (network identity).
	if len(prep.signals) != 1 || prep.signals[0].Kind != "observed_ip" {
		t.Errorf("expected only an observed_ip signal without a ClientHello, got %d signals", len(prep.signals))
	}
}

func TestPrepareEmitsH2Signals(t *testing.T) {
	h2fp := &fingerprint.H2Fingerprint{
		Settings:          []fingerprint.H2Setting{{ID: 1, Value: 65536}},
		WindowUpdate:      15663105,
		PseudoHeaderOrder: "m,a,s,p",
	}
	prep, err := prepare(req(t, "abc"), nil, h2fp, fingerprint.HintTable{}, fixedID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, s := range prep.signals {
		kinds[s.Kind] = true
	}
	// The h2 fingerprint (and the engine hint it implies) ride alongside the observed IP.
	if !kinds["h2"] || !kinds["h2_browser_hint"] {
		t.Errorf("expected h2 + h2_browser_hint signals, got %+v", kinds)
	}
}

func TestPrepareIDFailure(t *testing.T) {
	if _, err := prepare(req(t, ""), nil, nil, fingerprint.HintTable{}, failID, time.Now()); err == nil {
		t.Error("expected error when id minting fails")
	}
}

func TestReverseProxyServeHTTP(t *testing.T) {
	backendHit := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHit = true
		if r.Header.Get("X-KS-Session") == "" {
			t.Error("backend missing X-KS-Session header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	got := make(chan []byte, 1)
	detector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer detector.Close()

	rp, err := NewReverseProxy(backend.URL, detector.URL, fingerprint.HintTable{})
	if err != nil {
		t.Fatal(err)
	}
	rp.newID = fixedID
	rp.now = fixedNow

	r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	r = r.WithContext(context.WithValue(r.Context(), helloKey, helloFixture(t)))
	rr := httptest.NewRecorder()
	rp.ServeHTTP(rr, r)

	if !backendHit {
		t.Error("backend was not reached")
	}
	if !strings.Contains(rr.Header().Get("Set-Cookie"), session.CookieName) {
		t.Errorf("missing session cookie: %q", rr.Header().Get("Set-Cookie"))
	}
	select {
	case body := <-got:
		if !strings.Contains(string(body), `"layer":"network"`) {
			t.Errorf("detector did not receive network signals: %s", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("detector never received signals")
	}
}

func TestSelfSignedCert(t *testing.T) {
	cert, err := selfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("empty certificate")
	}
	if _, err := x509.ParseCertificate(cert.Certificate[0]); err != nil {
		t.Errorf("cert does not parse: %v", err)
	}
}

func TestAcceptLanguagePrimary(t *testing.T) {
	cases := map[string]string{
		"en-US,en;q=0.9": "en",
		"de-DE,de;q=0.8": "de",
		"fr":             "fr",
		"  EN-GB ":       "en",
		"":               "",
	}
	for header, want := range cases {
		r := httptest.NewRequest(http.MethodGet, "https://localhost/", nil)
		if header != "" {
			r.Header.Set("Accept-Language", header)
		}
		if got := acceptLanguagePrimary(r); got != want {
			t.Errorf("Accept-Language %q: got %q want %q", header, got, want)
		}
	}
}

func TestPrepareEmitsAcceptLanguage(t *testing.T) {
	r := req(t, "abc")
	r.Header.Set("Accept-Language", "de-DE,de;q=0.9")
	prep, err := prepare(r, nil, nil, fingerprint.HintTable{}, fixedID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range prep.signals {
		if s.Kind == "accept_language_primary" && s.Value == "de" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected accept_language_primary=de signal, got %+v", prep.signals)
	}
}

func TestSecCHUAPlatform(t *testing.T) {
	cases := map[string]string{
		`"Windows"`:   "Windows",
		`"macOS"`:     "macOS",
		`"Linux"`:     "Linux",
		`"Android"`:   "Android",
		`"Chrome OS"`: "", // outside the ua_platform vocabulary → emit nothing rather than mismatch
		`"iOS"`:       "",
		"":            "",
	}
	for header, want := range cases {
		r := httptest.NewRequest(http.MethodGet, "https://localhost/", nil)
		if header != "" {
			r.Header.Set("Sec-CH-UA-Platform", header)
		}
		if got := secCHUAPlatform(r); got != want {
			t.Errorf("Sec-CH-UA-Platform %q: got %q want %q", header, got, want)
		}
	}
}

func TestPrepareEmitsCHPlatform(t *testing.T) {
	r := req(t, "abc")
	r.Header.Set("Sec-CH-UA-Platform", `"macOS"`)
	prep, err := prepare(r, nil, nil, fingerprint.HintTable{}, fixedID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range prep.signals {
		if s.Kind == "ch_platform_header" && s.Value == "macOS" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ch_platform_header=macOS signal, got %+v", prep.signals)
	}
}

func TestSecFetchMissing(t *testing.T) {
	chromeUA := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	cases := []struct {
		name   string
		ua     string
		secHdr bool
		want   bool
	}{
		{"browser UA, no sec-fetch (scripted)", chromeUA, false, true},
		{"browser UA, with sec-fetch (real)", chromeUA, true, false},
		{"non-browser UA (httpx default)", "python-httpx/0.27", false, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "https://localhost/", nil)
		r.Header.Set("User-Agent", c.ua)
		if c.secHdr {
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Site", "none")
		}
		if got := secFetchMissing(r); got != c.want {
			t.Errorf("%s: secFetchMissing=%v want %v", c.name, got, c.want)
		}
	}
}
