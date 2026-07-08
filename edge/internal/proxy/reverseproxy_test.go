// edge/proxy/reverseproxy_test — tests for per-request fingerprint decoration (prepare).
// Covers session minting vs cookie reuse, signal emission, nil hello, and id-mint failure.

package proxy

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
	"github.com/datascry/kitsune/edge/internal/session"
	"github.com/datascry/kitsune/edge/internal/signal"
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
	prep, err := prepare(req(t, ""), helloFixture(t), nil, fingerprint.HintTable{}, fixedID, time.Now(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prep.sessionID != "fixed-session" || prep.setCookie == nil {
		t.Errorf("session=%s setCookie=%v", prep.sessionID, prep.setCookie)
	}
	if len(prep.signals) != 6 {
		t.Errorf("want ja3+ja4+ext-order+cipher-order+observed_ip+http_version, got %d", len(prep.signals))
	}
	have := map[string]bool{}
	for _, s := range prep.signals {
		have[s.Kind] = true
	}
	if !have["observed_ip"] || !have["http_version"] {
		t.Errorf("expected observed_ip + http_version signals, got kinds %v", have)
	}
}

func TestPrepareReusesCookie(t *testing.T) {
	prep, err := prepare(req(t, "abc"), helloFixture(t), nil, fingerprint.HintTable{}, fixedID, time.Now(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prep.sessionID != "abc" || prep.setCookie != nil {
		t.Errorf("session=%s setCookie=%v", prep.sessionID, prep.setCookie)
	}
}

func TestPrepareNilHello(t *testing.T) {
	prep, err := prepare(req(t, "abc"), nil, nil, fingerprint.HintTable{}, fixedID, time.Now(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// No ClientHello → no ja3/ja4, but the observed source IP + HTTP version are still captured (network
	// identity is independent of TLS).
	kinds := map[string]bool{}
	for _, s := range prep.signals {
		kinds[s.Kind] = true
	}
	if len(prep.signals) != 2 || !kinds["observed_ip"] || !kinds["http_version"] {
		t.Errorf("expected observed_ip + http_version without a ClientHello, got %d signals %v", len(prep.signals), kinds)
	}
}

func TestPrepareEmitsH2Signals(t *testing.T) {
	h2fp := &fingerprint.H2Fingerprint{
		Settings:          []fingerprint.H2Setting{{ID: 1, Value: 65536}},
		WindowUpdate:      15663105,
		PseudoHeaderOrder: "m,a,s,p",
	}
	prep, err := prepare(req(t, "abc"), nil, h2fp, fingerprint.HintTable{}, fixedID, time.Now(), nil, nil)
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

func TestPrepareEmitsH2EngineUnknown(t *testing.T) {
	const chromeUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	unknownH2 := &fingerprint.H2Fingerprint{PseudoHeaderOrder: "a,m,p,s"} // Go's http2 order
	chromeH2 := &fingerprint.H2Fingerprint{PseudoHeaderOrder: "m,a,s,p"}  // a real Chromium
	emits := func(ua string, fp *fingerprint.H2Fingerprint) bool {
		r := req(t, "abc")
		if ua != "" {
			r.Header.Set("User-Agent", ua)
		}
		prep, err := prepare(r, nil, fp, fingerprint.HintTable{}, fixedID, time.Now(), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range prep.signals {
			if s.Kind == "h2_engine_unknown" {
				return true
			}
		}
		return false
	}
	if !emits(chromeUA, unknownH2) {
		t.Error("chrome UA + unknown h2 order should emit h2_engine_unknown")
	}
	if emits(chromeUA, chromeH2) {
		t.Error("chrome UA + chrome h2 order must not emit h2_engine_unknown")
	}
	if emits("", unknownH2) {
		t.Error("non-browser UA must not emit h2_engine_unknown (gated on a browser UA)")
	}
	// Real Safari's on-wire h2 order is unverified (classified "unknown"); convicting an unknown order under
	// a Safari UA false-positived every real Safari, so the emission carves Safari out (like the Firefox
	// GREASE carve-out). A Safari-UA-faking bot is still caught by its JA4 mismatch + the no-JS tells.
	const safariUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
	if emits(safariUA, unknownH2) {
		t.Error("Safari UA + unknown h2 order must NOT emit h2_engine_unknown (real Safari is unfingerprintable here)")
	}
}

type stubResolver struct{ addrErr error }

func (s stubResolver) LookupAddr(context.Context, string) ([]string, error) { return nil, s.addrErr }
func (s stubResolver) LookupHost(context.Context, string) ([]string, error) { return nil, nil }

func TestPrepareEmitsFakeDeclaredCrawler(t *testing.T) {
	// A non-Google IP wearing a Googlebot UA with no PTR record → FCrDNS-fail → fake_declared_crawler.
	emits := func(ua string) bool {
		r := req(t, "abc")
		r.RemoteAddr = "203.0.113.7:443" // a non-crawler address
		r.Header.Set("User-Agent", ua)
		res := &fingerprint.CrawlerVerifier{Resolver: stubResolver{addrErr: &net.DNSError{IsNotFound: true}}}
		prep, err := prepare(r, nil, nil, fingerprint.HintTable{}, fixedID, time.Now(), res, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range prep.signals {
			if s.Kind == "fake_declared_crawler" {
				return true
			}
		}
		return false
	}
	if !emits("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)") {
		t.Error("a Googlebot UA from an IP with no crawler PTR should emit fake_declared_crawler")
	}
	if emits("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36") {
		t.Error("a plain browser UA must not emit fake_declared_crawler")
	}
}

func TestPrepareIDFailure(t *testing.T) {
	if _, err := prepare(req(t, ""), nil, nil, fingerprint.HintTable{}, failID, time.Now(), nil, nil); err == nil {
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

func TestServeHTTPEmitsRapidReset(t *testing.T) {
	got := make(chan []byte, 1)
	detector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer detector.Close()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer backend.Close()

	rp, err := NewReverseProxy(backend.URL, detector.URL, fingerprint.HintTable{})
	if err != nil {
		t.Fatal(err)
	}
	rp.newID = fixedID
	rp.now = fixedNow

	// A connection whose frame scanner has seen a rapid-reset flood → the per-request handler flags it.
	scanner := &fingerprint.H2FrameScanner{}
	scanner.Feed(rapidResetStream(t, 120))
	if !scanner.RapidReset() {
		t.Fatal("precondition: scanner should report rapid-reset")
	}
	r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	ctx := context.WithValue(r.Context(), helloKey, helloFixture(t))
	ctx = context.WithValue(ctx, scannerKey, scanner)
	rp.ServeHTTP(httptest.NewRecorder(), r.WithContext(ctx))

	select {
	case body := <-got:
		if !strings.Contains(string(body), `"kind":"h2_rapid_reset"`) {
			t.Errorf("expected an h2_rapid_reset signal, got: %s", body)
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
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("cert does not parse: %v", err)
	}
	// The SAN must cover both the compose service name (edge) and localhost, so a hostname-verifying
	// client can reach the proxy by either without disabling TLS verification.
	for _, want := range []string{"edge", "localhost"} {
		if err := parsed.VerifyHostname(want); err != nil {
			t.Errorf("cert is not valid for %q: %v", want, err)
		}
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
	prep, err := prepare(r, nil, nil, fingerprint.HintTable{}, fixedID, time.Now(), nil, nil)
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

func TestSecCHUABrowser(t *testing.T) {
	cases := map[string]string{
		`"Chromium";v="126", "Google Chrome";v="126", "Not.A/Brand";v="99"`:  "chrome",
		`"Microsoft Edge";v="126", "Chromium";v="126", "Not.A/Brand";v="24"`: "edge",
		`"Chromium";v="126", "Not;A=Brand";v="99", "Brave";v="126"`:          "chrome",
		`"Weird Brand";v="1"`: "", // present but unrecognised → no signal
		"":                    "",
	}
	for header, want := range cases {
		r := httptest.NewRequest(http.MethodGet, "https://localhost/", nil)
		if header != "" {
			r.Header.Set("Sec-CH-UA", header)
		}
		if got := secCHUABrowser(r); got != want {
			t.Errorf("Sec-CH-UA %q: got %q want %q", header, got, want)
		}
	}
}

func TestCHUAVersionMismatch(t *testing.T) {
	chrome126 := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	v126 := `"Chromium";v="126", "Google Chrome";v="126", "Not.A/Brand";v="99"`
	v124 := `"Chromium";v="124", "Google Chrome";v="124", "Not.A/Brand";v="99"`
	cases := []struct {
		name   string
		ua     string
		chua   string
		expect bool
	}{
		{"coherent versions", chrome126, v126, false},
		{"mismatched versions (scraper headers)", chrome126, v124, true},
		{"no Sec-CH-UA (Firefox/Safari/scripted)", chrome126, "", false},
		{"non-Chrome UA", "Mozilla/5.0 (X11; Linux) Gecko/20100101 Firefox/127.0", v126, false},
		{"GREASE brand only is ignored", chrome126, `"Not.A/Brand";v="99"`, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "https://localhost/", nil)
		r.Header.Set("User-Agent", c.ua)
		if c.chua != "" {
			r.Header.Set("Sec-CH-UA", c.chua)
		}
		if got := chUAVersionMismatch(r); got != c.expect {
			t.Errorf("%s: chUAVersionMismatch=%v want %v", c.name, got, c.expect)
		}
	}
}

func TestPrepareEmitsCHUABrowser(t *testing.T) {
	r := req(t, "abc")
	r.Header.Set("Sec-CH-UA", `"Chromium";v="126", "Google Chrome";v="126", "Not.A/Brand";v="99"`)
	prep, err := prepare(r, nil, nil, fingerprint.HintTable{}, fixedID, time.Now(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range prep.signals {
		if s.Kind == "ch_ua_browser" && s.Value == "chrome" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ch_ua_browser=chrome signal, got %+v", prep.signals)
	}
}

func TestPrepareEmitsUAHeaderBrowser(t *testing.T) {
	r := req(t, "abc")
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	prep, err := prepare(r, nil, nil, fingerprint.HintTable{}, fixedID, time.Now(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range prep.signals {
		if s.Kind == "ua_header_browser" && s.Value == "chrome" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ua_header_browser=chrome signal, got %+v", prep.signals)
	}
	// A non-browser UA makes no browser claim → the signal must be withheld (nothing to contradict).
	r2 := req(t, "abc")
	r2.Header.Set("User-Agent", "curl/8.7.1")
	prep2, err := prepare(r2, nil, nil, fingerprint.HintTable{}, fixedID, time.Now(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range prep2.signals {
		if s.Kind == "ua_header_browser" {
			t.Errorf("a non-browser UA must not emit ua_header_browser, got %+v", s)
		}
	}
}

func TestPrepareEmitsCHPlatform(t *testing.T) {
	r := req(t, "abc")
	r.Header.Set("Sec-CH-UA-Platform", `"macOS"`)
	prep, err := prepare(r, nil, nil, fingerprint.HintTable{}, fixedID, time.Now(), nil, nil)
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

func TestCHUAMobileMismatch(t *testing.T) {
	chUA := `"Chromium";v="126", "Google Chrome";v="126"`
	desktopUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36"
	mobileUA := "Mozilla/5.0 (Linux; Android 14) Chrome/126.0.0.0 Mobile Safari/537.36"
	cases := []struct {
		name, ua, chUA, mobile string
		want                   bool
	}{
		{"desktop coherent", desktopUA, chUA, "?0", false},
		{"mobile coherent", mobileUA, chUA, "?1", false},
		{"mobile UA but ?0 (desktop stack)", mobileUA, chUA, "?0", true},
		{"desktop UA but ?1", desktopUA, chUA, "?1", true},
		{"no Sec-CH-UA (Firefox/scripted)", desktopUA, "", "?0", false},
		{"no mobile hint", desktopUA, chUA, "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "https://localhost/", nil)
		r.Header.Set("User-Agent", c.ua)
		if c.chUA != "" {
			r.Header.Set("Sec-CH-UA", c.chUA)
		}
		if c.mobile != "" {
			r.Header.Set("Sec-CH-UA-Mobile", c.mobile)
		}
		if got := chUAMobileMismatch(r); got != c.want {
			t.Errorf("%s: chUAMobileMismatch=%v want %v", c.name, got, c.want)
		}
	}
}

func TestCHUANoGREASEBrand(t *testing.T) {
	chromeUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36"
	firefoxUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/126.0"
	cases := []struct {
		name, ua, chUA string
		want           bool
	}{
		{"real Chromium GREASE brand", chromeUA, `"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"`, false},
		{"real Chromium alt GREASE punctuation", chromeUA, `"Chromium";v="126", "Not.A/Brand";v="24", "Google Chrome";v="126"`, false},
		{"hardcoded header, no GREASE brand", chromeUA, `"Google Chrome";v="126", "Chromium";v="126"`, true},
		{"no Sec-CH-UA (Firefox)", firefoxUA, "", false},
		{"hardcoded header under non-Chromium UA still fires", firefoxUA, `"Google Chrome";v="126"`, true},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "https://localhost/", nil)
		r.Header.Set("User-Agent", c.ua)
		if c.chUA != "" {
			r.Header.Set("Sec-CH-UA", c.chUA)
		}
		if got := chUANoGREASEBrand(r); got != c.want {
			t.Errorf("%s: chUANoGREASEBrand=%v want %v", c.name, got, c.want)
		}
	}
}

func TestChromeUAExpectsPQ(t *testing.T) {
	cases := map[string]bool{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36": true,
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0.0.0 Safari/537.36": true,
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36": false,
		"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/131.0":             false,
		"": false,
	}
	for ua, want := range cases {
		if got := chromeUAExpectsPQ(ua); got != want {
			t.Errorf("chromeUAExpectsPQ(%q)=%v want %v", ua, got, want)
		}
	}
}

func TestUAKernel(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125":          "windows",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605":    "darwin",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari": "darwin",
		"Mozilla/5.0 (Linux; Android 14) Chrome/125 Mobile":             "linux", // Android = Linux kernel
		"Mozilla/5.0 (X11; Linux x86_64) Firefox/127":                   "linux",
		"python-httpx/0.27": "",
	}
	for ua, want := range cases {
		if got := uaKernel(ua); got != want {
			t.Errorf("uaKernel(%q)=%q want %q", ua, got, want)
		}
	}
}

func TestAcceptEncodingNoBrotli(t *testing.T) {
	chromeUA := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	cases := []struct {
		name string
		ua   string
		enc  string
		want bool
	}{
		{"browser, full browser encodings", chromeUA, "gzip, deflate, br, zstd", false},
		{"browser, br with q-value", chromeUA, "gzip, deflate, br;q=1.0", false},
		{"browser, no brotli (scripted)", chromeUA, "gzip, deflate", true},
		{"browser, identity only (scripted)", chromeUA, "identity", true},
		{"browser, empty header (scripted)", chromeUA, "", true},
		{"non-browser UA is out of scope", "python-httpx/0.27", "gzip, deflate", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "https://localhost/", nil)
		r.Header.Set("User-Agent", c.ua)
		if c.enc != "" {
			r.Header.Set("Accept-Encoding", c.enc)
		}
		if got := acceptEncodingNoBrotli(r); got != c.want {
			t.Errorf("%s: acceptEncodingNoBrotli=%v want %v", c.name, got, c.want)
		}
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

func TestUAGreasesHandshake(t *testing.T) {
	// Chromium + Safari engines GREASE TLS; Gecko/Firefox does NOT (v0.74.31 FP fix). The tls_no_grease tell
	// must therefore be withheld from a Firefox UA but kept for the GREASEing engines and non-browser stacks.
	cases := []struct {
		name string
		ua   string
		want bool
	}{
		{"real Chrome", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36", true},
		{"real Edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0", true},
		{"real Safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15", true},
		{"real Firefox — does NOT GREASE TLS", "Mozilla/5.0 (X11; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0", false},
		{"non-browser stack", "python-httpx/0.27", false},
	}
	for _, c := range cases {
		if got := uaGreasesHandshake(c.ua); got != c.want {
			t.Errorf("%s: uaGreasesHandshake=%v want %v", c.name, got, c.want)
		}
	}
}

func TestUAHeaderBrowser(t *testing.T) {
	// Classify the UA HEADER into the browser vocabulary (or "" for a non-browser client). Edge must precede
	// Chrome (Edge UAs embed Chrome/); Safari needs Version/ and must lose to Chrome (Chrome embeds Safari/).
	cases := []struct {
		name, ua, want string
	}{
		{"chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "chrome"},
		{"edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0", "edge"},
		{"firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0", "firefox"},
		{"safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15", "safari"},
		{"curl (non-browser)", "curl/8.7.1", ""},
		{"python urllib (non-browser)", "Python-urllib/3.12", ""},
		{"go http (non-browser)", "Go-http-client/1.1", ""},
		{"bare Safari token without Version (not a browser claim)", "SomeBot/1.0 Safari/537.36", ""},
	}
	for _, c := range cases {
		if got := uaHeaderBrowser(c.ua); got != c.want {
			t.Errorf("%s: uaHeaderBrowser=%q want %q", c.name, got, c.want)
		}
	}
}

func TestJA4TWindowScale(t *testing.T) {
	cases := []struct {
		ja4t    string
		scale   int
		present bool
	}{
		{"64240_2-1-3-1-1-8-4-0_1460_6", 6, true}, // forged darwin (os-spoof macos)
		{"64240_2-4-8-1-3_1460_7", 7, true},       // real linux
		{"65535_2-1-3_1460_00", 0, false},         // no window-scale option
		{"garbage", 0, false},
	}
	for _, c := range cases {
		s, p := ja4tWindowScale(c.ja4t)
		if s != c.scale || p != c.present {
			t.Errorf("ja4tWindowScale(%q)=(%d,%v) want (%d,%v)", c.ja4t, s, p, c.scale, c.present)
		}
	}
}

func TestSanitizeClientIngestStripsServerLayers(t *testing.T) {
	// A client-proxied /ingest body carrying FORGED server-authoritative signals (network JA4 + a clean
	// reputation) alongside legitimate browser+behavioral signals — only browser+behavioral must survive.
	body := `[` +
		`{"session_id":"s","layer":"network","kind":"ja4","value":"forged","source":"collector","observed_at":"2026-01-01T00:00:00Z"},` +
		`{"session_id":"s","layer":"reputation","kind":"asn_is_datacenter","value":false,"source":"collector","observed_at":"2026-01-01T00:00:00Z"},` +
		`{"session_id":"s","layer":"browser","kind":"user_agent","value":"UA","source":"collector","observed_at":"2026-01-01T00:00:00Z"},` +
		`{"session_id":"s","layer":"behavioral","kind":"trace_hash","value":"abc","source":"collector","observed_at":"2026-01-01T00:00:00Z"}]`
	r := httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader(body))
	sanitizeClientIngest(httptest.NewRecorder(), r)
	out, _ := io.ReadAll(r.Body)
	var sigs []signal.Signal
	if err := json.Unmarshal(out, &sigs); err != nil {
		t.Fatalf("rewritten body not valid signal JSON: %v", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("expected only browser+behavioral to survive, got %+v", sigs)
	}
	for _, s := range sigs {
		if s.Layer != "browser" && s.Layer != "behavioral" {
			t.Fatalf("server-authoritative layer %q survived: %+v", s.Layer, s)
		}
	}
	if int(r.ContentLength) != len(out) {
		t.Fatalf("Content-Length %d != body len %d", r.ContentLength, len(out))
	}
}

func TestSanitizeClientIngestLeavesOtherPathsUntouched(t *testing.T) {
	// A GET, a non-/ingest POST, and a non-signal body must pass through byte-for-byte.
	for _, tc := range []struct {
		method, path, body string
	}{
		{http.MethodGet, "/ingest", ""},
		{http.MethodPost, "/other", `[{"layer":"network"}]`},
		{http.MethodPost, "/ingest", `not json`},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		sanitizeClientIngest(httptest.NewRecorder(), r)
		out, _ := io.ReadAll(r.Body)
		if string(out) != tc.body {
			t.Fatalf("%s %s: body altered %q -> %q", tc.method, tc.path, tc.body, string(out))
		}
	}
}

func TestIsAdminPathBlocksInternal(t *testing.T) {
	for _, p := range []string{"/scoreboard", "/session/abc", "/verdict/abc", "/docs", "/redoc",
		"/openapi.json", "/Session/abc", "//scoreboard", "/session/../verdict/x", "/session", "/verdict"} {
		if !isAdminPath(p) {
			t.Errorf("admin path %q not blocked", p)
		}
	}
	for _, p := range []string{"/", "/ingest", "/inspect/abc", "/arena/gate", "/rules.json", "/healthz", "/sessionish"} {
		if isAdminPath(p) {
			t.Errorf("public path %q wrongly blocked", p)
		}
	}
}

func TestServeHTTPBlocksAdminPaths(t *testing.T) {
	backendHit := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { backendHit = true }))
	defer backend.Close()
	rp, err := NewReverseProxy(backend.URL, "", fingerprint.HintTable{})
	if err != nil {
		t.Fatal(err)
	}
	rp.newID = fixedID
	rp.now = fixedNow
	rr := httptest.NewRecorder()
	rp.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://localhost/scoreboard", nil))
	if rr.Code != http.StatusNotFound {
		t.Errorf("want 404 for /scoreboard, got %d", rr.Code)
	}
	if backendHit {
		t.Error("admin path reached the backend")
	}
}

func TestSanitizeClientIngestRejectsOversizedBody(t *testing.T) {
	// A body over the cap must be rejected with 413 and NOT proxied; a normal body must pass.
	big := strings.Repeat("x", maxIngestBody+100)
	r := httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader(`[{"blob":"`+big+`"}]`))
	rr := httptest.NewRecorder()
	if !sanitizeClientIngest(rr, r) {
		t.Fatal("oversized body was not rejected")
	}
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("want 413, got %d", rr.Code)
	}
	small := httptest.NewRequest(http.MethodPost, "/ingest",
		strings.NewReader(`[{"session_id":"s","layer":"browser","kind":"ua","value":"U","source":"collector","observed_at":"2026-01-01T00:00:00Z"}]`))
	if sanitizeClientIngest(httptest.NewRecorder(), small) {
		t.Error("a normal-sized body was wrongly rejected")
	}
}
