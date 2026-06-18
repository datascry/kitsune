// edge/proxy/reverseproxy — transparent TLS-terminating reverse proxy with fingerprint capture.
// Peeks the ClientHello, mints/keeps ks_sid, forwards network signals, proxies HTTP to a backend.

package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
	"github.com/datascry/kitsune/edge/internal/peek"
	"github.com/datascry/kitsune/edge/internal/session"
	"github.com/datascry/kitsune/edge/internal/signal"
)

type ctxKey int

const (
	helloKey ctxKey = iota
	h2Key
	scannerKey
)

// prepared is the per-request fingerprint decoration the proxy applies.
type prepared struct {
	sessionID string
	signals   []signal.Signal
	setCookie *http.Cookie // non-nil when a new session id was minted
}

// prepare derives the session id (from the ks_sid cookie or freshly minted) and the network signals
// for a request whose connection produced the given ClientHello. Pure + testable.
func prepare(
	r *http.Request,
	hello *fingerprint.ClientHello,
	h2fp *fingerprint.H2Fingerprint,
	hints fingerprint.HintTable,
	newID IDFunc,
	now time.Time,
) (prepared, error) {
	var out prepared
	if c, err := r.Cookie(session.CookieName); err == nil {
		out.sessionID = c.Value
	} else {
		id, err := newID()
		if err != nil {
			return out, err
		}
		out.sessionID = id
		// Not HttpOnly: the in-page collector reads ks_sid to tag its telemetry with the session.
		out.setCookie = &http.Cookie{Name: session.CookieName, Value: id, Path: "/"}
	}
	if hello != nil {
		out.signals = signal.FromClientHello(out.sessionID, hello, hints, now)
	}
	// The HTTP/2 connection preface (SETTINGS / WINDOW_UPDATE / PRIORITY / pseudo-header order) is a
	// client-stack fingerprint below the application layer: a UA-spoofer that runs a Chrome HTTP/2
	// stack while claiming Firefox (or vice-versa) contradicts itself here, independent of TLS and JS.
	if h2fp != nil {
		out.signals = append(out.signals, signal.FromH2(out.sessionID, *h2fp, now)...)
	}
	// The observed source IP is the network-layer identity: the address the connection actually came
	// from. A bot proxying its HTTP through a residential exit shows the proxy IP here, while WebRTC
	// can leak its real IP in the browser layer — the detector cross-checks the two (a proxied-bot tell).
	if ip := clientIP(r); ip != "" {
		out.signals = append(out.signals, signal.Network(out.sessionID, "observed_ip", ip, now))
	}
	if secFetchMissing(r) {
		out.signals = append(out.signals, signal.Network(out.sessionID, "sec_fetch_missing", true, now))
	}
	if acceptEncodingNoBrotli(r) {
		out.signals = append(out.signals, signal.Network(out.sessionID, "accept_encoding_no_brotli", true, now))
	}
	// The primary language the HTTP stack advertises (Accept-Language). The detector cross-checks it
	// against the JS-layer navigator.languages: a bot that spoofs its locale in the browser but lets its
	// HTTP client send a default Accept-Language contradicts itself across the network/browser boundary.
	if lang := acceptLanguagePrimary(r); lang != "" {
		out.signals = append(out.signals, signal.Network(out.sessionID, "accept_language_primary", lang, now))
	}
	// The OS the HTTP stack advertises via the Sec-CH-UA-Platform client hint. Chrome sets this from the
	// real OS at the network layer, so a JS-only UA/platform spoof (CDP setUserAgent without
	// userAgentMetadata) leaves it disagreeing with the spoofed navigator platform — a cross-layer tell.
	if plat := secCHUAPlatform(r); plat != "" {
		out.signals = append(out.signals, signal.Network(out.sessionID, "ch_platform_header", plat, now))
	}
	// The browser the HTTP stack advertises via the Sec-CH-UA brand list. Chromium sets it from its real
	// brand, so a Chromium browser presenting a non-Chrome User-Agent (CDP setUserAgent without
	// userAgentMetadata) sends Sec-CH-UA "Chromium"/"Google Chrome" under, say, a Firefox UA — caught by
	// the detector cross-checking this against the JS ua_browser.
	if b := secCHUABrowser(r); b != "" {
		out.signals = append(out.signals, signal.Network(out.sessionID, "ch_ua_browser", b, now))
	}
	if chUAVersionMismatch(r) {
		out.signals = append(out.signals, signal.Network(out.sessionID, "ch_ua_version_mismatch", true, now))
	}
	return out, nil
}

// secCHUABrowser maps the Sec-CH-UA brand list to the same browser vocabulary the collector reports for
// browser.ua_browser. Only Chromium-family browsers send this header at all; "Microsoft Edge" in the
// brand list means Edge, any other Chromium brand (Google Chrome, Chromium, Brave, …) maps to chrome.
// An empty or unrecognised header yields "" so it is not emitted (Firefox/Safari never send it, and a
// blank value must not be compared).
func secCHUABrowser(r *http.Request) string {
	v := r.Header.Get("Sec-CH-UA")
	switch {
	case v == "":
		return ""
	case strings.Contains(v, "Microsoft Edge"):
		return "edge"
	case strings.Contains(v, "Chromium") || strings.Contains(v, "Google Chrome"):
		return "chrome"
	default:
		return ""
	}
}

// secCHUAMajorVersion returns the major version of the *real* Chromium-family brand in the Sec-CH-UA
// list (skipping the deliberately-fake "Not.A/Brand" GREASE entry), e.g. `"Chromium";v="126"` -> "126".
// The low-entropy Sec-CH-UA carries only the major version, which is what we compare against the UA.
func secCHUAMajorVersion(secCHUA string) string {
	for _, brand := range []string{"Google Chrome", "Microsoft Edge", "Chromium"} {
		i := strings.Index(secCHUA, `"`+brand+`"`)
		if i < 0 {
			continue
		}
		j := strings.Index(secCHUA[i:], `v="`)
		if j < 0 {
			continue
		}
		ver := secCHUA[i+j+3:]
		if k := strings.IndexByte(ver, '"'); k >= 0 {
			return ver[:k]
		}
	}
	return ""
}

// uaChromeMajorVersion returns the major version from a `Chrome/<n>` token in the User-Agent, or "".
func uaChromeMajorVersion(ua string) string {
	i := strings.Index(ua, "Chrome/")
	if i < 0 {
		return ""
	}
	ver := ua[i+len("Chrome/"):]
	end := strings.IndexAny(ver, ". ")
	if end < 0 {
		end = len(ver)
	}
	return ver[:end]
}

// chUAVersionMismatch reports a request whose UA-string Chrome version disagrees with the Sec-CH-UA brand
// version. A real Chromium keeps the two identical; a scraper that assembles a header set from mismatched
// sources (a UA from one Chrome version, a copied Sec-CH-UA from another) splits them — a common tell.
func chUAVersionMismatch(r *http.Request) bool {
	chv := secCHUAMajorVersion(r.Header.Get("Sec-CH-UA"))
	uav := uaChromeMajorVersion(r.Header.Get("User-Agent"))
	return chv != "" && uav != "" && chv != uav
}

// secCHUAPlatform returns the Sec-CH-UA-Platform client-hint value normalised to the same OS vocabulary
// the collector reports for browser.ua_platform (Windows/macOS/Linux/Android), or "" when the header is
// absent or names an OS outside that vocabulary (Chrome OS, iOS) — emitting nothing there avoids a
// spurious mismatch against a ua_platform the collector could not classify either.
func secCHUAPlatform(r *http.Request) string {
	v := strings.Trim(strings.TrimSpace(r.Header.Get("Sec-CH-UA-Platform")), `"`)
	switch v {
	case "Windows", "macOS", "Linux", "Android":
		return v
	default:
		return ""
	}
}

// acceptLanguagePrimary returns the lower-cased primary language subtag of the Accept-Language header
// (e.g. "en-US,en;q=0.9" -> "en"), or "" when absent. Comparing only the subtag (not the region) keeps
// the cross-layer check robust: it flags a different language entirely, not an en-US vs en-GB nuance.
func acceptLanguagePrimary(r *http.Request) string {
	al := r.Header.Get("Accept-Language")
	if al == "" {
		return ""
	}
	// First tag, before any q-value list; then the language subtag, before any region.
	first, _, _ := strings.Cut(al, ",")
	first, _, _ = strings.Cut(strings.TrimSpace(first), ";")
	subtag, _, _ := strings.Cut(strings.TrimSpace(first), "-")
	return strings.ToLower(subtag)
}

// clientIP extracts the source IP (without port) from the request's remote address.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// isModernBrowserUA reports whether the User-Agent claims a current Chrome/Firefox/Edge/Safari. The
// HTTP-layer coherence rules target *fakery* — a scripted client wearing a browser UA — so a non-browser
// UA (which makes no such claim) is out of scope for them.
func isModernBrowserUA(ua string) bool {
	return strings.Contains(ua, "Chrome/") || strings.Contains(ua, "Firefox/") ||
		strings.Contains(ua, "Edg/") || (strings.Contains(ua, "Safari/") && strings.Contains(ua, "Version/"))
}

// secFetchMissing reports a request whose User-Agent claims a modern browser but which omits the
// Sec-Fetch metadata headers every such browser sends on real requests. A scripted HTTP client (the
// volumetric-DDoS case) that fakes a browser UA over plain httpx/curl gives itself away here — an
// HTTP-layer tell, independent of the TLS and JS layers.
func secFetchMissing(r *http.Request) bool {
	if !isModernBrowserUA(r.Header.Get("User-Agent")) {
		return false // a non-browser UA is a different (and weaker) signal; this rule targets fakery
	}
	return r.Header.Get("Sec-Fetch-Mode") == "" && r.Header.Get("Sec-Fetch-Site") == ""
}

// acceptEncodingNoBrotli reports a request whose UA claims a modern browser but whose Accept-Encoding
// omits Brotli (`br`). Every current browser advertises `br` (and now `zstd`) over HTTPS; a scripted
// client faking a browser UA over httpx/requests/curl typically sends only `gzip, deflate` — an
// HTTP-compression fingerprint tell, independent of the Sec-Fetch and TLS signals.
func acceptEncodingNoBrotli(r *http.Request) bool {
	if !isModernBrowserUA(r.Header.Get("User-Agent")) {
		return false
	}
	for _, tok := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		enc, _, _ := strings.Cut(strings.TrimSpace(tok), ";") // drop any q-value
		if strings.EqualFold(enc, "br") {
			return false
		}
	}
	return true
}

// ReverseProxy is a transparent TLS edge in front of a backend app.
type ReverseProxy struct {
	backend     *httputil.ReverseProxy
	detectorURL string
	hints       fingerprint.HintTable
	newID       IDFunc
	now         func() time.Time
	client      *http.Client
}

// NewReverseProxy builds a reverse proxy forwarding to backendURL and reporting to detectorURL.
func NewReverseProxy(backendURL, detectorURL string, hints fingerprint.HintTable) (*ReverseProxy, error) {
	target, err := url.Parse(backendURL)
	if err != nil {
		return nil, err
	}
	return &ReverseProxy{
		backend:     httputil.NewSingleHostReverseProxy(target),
		detectorURL: detectorURL,
		hints:       hints,
		newID:       session.NewID,
		now:         time.Now,
		client:      &http.Client{Timeout: 5 * time.Second},
	}, nil
}

func (p *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hello, _ := r.Context().Value(helloKey).(*fingerprint.ClientHello)
	h2fp, _ := r.Context().Value(h2Key).(*fingerprint.H2Fingerprint)
	prep, err := prepare(r, hello, h2fp, p.hints, p.newID, p.now())
	if err != nil {
		http.Error(w, "could not mint session id", http.StatusInternalServerError)
		return
	}
	if prep.setCookie != nil {
		http.SetCookie(w, prep.setCookie)
		r.AddCookie(prep.setCookie)
	}
	r.Header.Set("X-KS-Session", prep.sessionID)
	// A rapid-reset flood (CVE-2023-44487) is connection-level abuse; flag it for the session this
	// connection carries (anonymous pure floods, with no completed request, are a rate limiter's job).
	if sc, ok := r.Context().Value(scannerKey).(*fingerprint.H2FrameScanner); ok {
		if sc.RapidReset() {
			prep.signals = append(prep.signals, signal.Network(prep.sessionID, "h2_rapid_reset", true, p.now()))
		}
		if sc.ContinuationFlood() {
			prep.signals = append(prep.signals, signal.Network(prep.sessionID, "h2_continuation_flood", true, p.now()))
		}
		if sc.ControlFrameFlood() {
			prep.signals = append(prep.signals, signal.Network(prep.sessionID, "h2_control_flood", true, p.now()))
		}
	}
	p.forward(prep.signals)
	p.backend.ServeHTTP(w, r)
}

func (p *ReverseProxy) forward(sigs []signal.Signal) {
	if p.detectorURL == "" || len(sigs) == 0 {
		return
	}
	body, err := signal.Marshal(sigs)
	if err != nil {
		return
	}
	resp, err := p.client.Post(p.detectorURL+"/ingest", "application/json", bytes.NewReader(body))
	if err == nil {
		_ = resp.Body.Close()
	}
}

// ListenAndServe runs the proxy on addr with TLS terminated using an ephemeral self-signed cert.
func (p *ReverseProxy) ListenAndServe(addr string) error { // pragma: integration
	cert, err := selfSignedCert()
	if err != nil {
		return err
	}
	inner, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	ln := tls.NewListener(peek.NewListener(inner), cfg)

	srv := &http.Server{
		Handler:     p,
		ReadTimeout: 15 * time.Second,
		// HTTP/2 is served by our own ALPN handler (serveH2) rather than the bundled h2 server: it
		// fingerprints the connection preface and threads both the ClientHello and the h2 fingerprint
		// through the base context, so per-request signals survive (the stdlib h2 server drops the
		// ConnContext value on its streams). HTTP/1.1 keeps the ConnContext path below.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){"h2": p.serveH2},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc, ok := c.(*tls.Conn); ok {
				if pc, ok := tc.NetConn().(*peek.Conn); ok {
					return context.WithValue(ctx, helloKey, pc.ClientHello())
				}
			}
			return ctx
		},
	}
	return srv.Serve(ln)
}

func selfSignedCert() (*tls.Certificate, error) { // pragma: integration
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kitsune-edge"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
