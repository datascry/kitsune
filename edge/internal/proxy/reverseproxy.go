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
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
	"github.com/datascry/kitsune/edge/internal/peek"
	"github.com/datascry/kitsune/edge/internal/session"
	"github.com/datascry/kitsune/edge/internal/signal"
	"github.com/datascry/kitsune/edge/internal/tcpfp"
	"github.com/datascry/kitsune/edge/internal/webbotauth"
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
	resolver fingerprint.Resolver,
	wbaReplay *webbotauth.ReplayStore,
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
		// Secure + SameSite=Lax: the edge is HTTPS-only, so the session cookie rides only over TLS
		// and is not sent on cross-site requests.
		out.setCookie = &http.Cookie{
			Name:     session.CookieName,
			Value:    id,
			Path:     "/",
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}
	}
	if hello != nil {
		out.signals = signal.FromClientHello(out.sessionID, hello, hints, now)
		// A GREASEing-engine UA (Chromium/Safari) over a handshake with no TLS GREASE: those engines inject
		// GREASE (RFC 8701) but a scripted TLS stack (OpenSSL/Go) does not — a TLS-layer tell for a UA-faking
		// client whose JA4 is otherwise unrecognised. Firefox is EXCLUDED: it does not GREASE TLS by default,
		// so emitting this on a Firefox UA false-fired on every real Firefox (see uaGreasesHandshake).
		if uaGreasesHandshake(r.Header.Get("User-Agent")) && !hello.HasGREASE() {
			out.signals = append(out.signals, signal.Network(out.sessionID, "tls_no_grease", true, now))
		}
		// A current-Chrome UA over a handshake that offers no post-quantum key share. Chrome 131+ sends
		// X25519MLKEM768 (124-130 the Kyber768 draft) in supported_groups by default; a static-template TLS
		// stack (curl-impersonate/utls/Go crypto/tls) pinned to an older Chrome profile lags this rollout —
		// a TLS tell the impersonation libraries must keep chasing. Scoped to >=131 so an older real Chrome
		// is never flagged; kept experimental because a corporate TLS-inspection proxy or
		// PostQuantumKeyAgreementEnabled=false also strips the group.
		if chromeUAExpectsPQ(r.Header.Get("User-Agent")) && !hello.HasPostQuantumKeyShare() {
			out.signals = append(out.signals, signal.Network(out.sessionID, "tls_no_pq_keyshare", true, now))
		}
	}
	// The HTTP/2 connection preface (SETTINGS / WINDOW_UPDATE / PRIORITY / pseudo-header order) is a
	// client-stack fingerprint below the application layer: a UA-spoofer that runs a Chrome HTTP/2
	// stack while claiming Firefox (or vice-versa) contradicts itself here, independent of TLS and JS.
	if h2fp != nil {
		out.signals = append(out.signals, signal.FromH2(out.sessionID, *h2fp, now)...)
		// A modern-browser UA whose HTTP/2 stack matches no known browser engine (pseudo-header order
		// outside Chrome/Firefox/Safari's). Every real browser has a recognised h2 order; a Go/Python
		// http2 client — or a browser fronted by a non-browser h2 proxy — does not. This is the h2 analog
		// of tls_no_grease: a browser UA over a non-browser stack, and a second network-layer tell beyond
		// no_js_execution (which only fires when no JS ran at all).
		if h2fp.Browser() == "unknown" && uaHasKnownH2Order(r.Header.Get("User-Agent")) {
			out.signals = append(out.signals, signal.Network(out.sessionID, "h2_engine_unknown", true, now))
		}
		// JA4H header-order tell: a UA claiming Chromium whose regular header order is not chromium-shaped
		// (Sec-CH-UA before user-agent) is a non-browser h2 stack wearing a Chrome UA. Gated to Chromium
		// because Firefox/Safari legitimately have a different (here "unknown") header order.
		if ua := r.Header.Get("User-Agent"); uaClaimsChromium(ua) && h2fp.HeaderOrderBrowser() != "chrome" {
			out.signals = append(out.signals, signal.Network(out.sessionID, "h2_header_order_non_chromium", true, now))
		}
	}
	// The observed source IP is the network-layer identity: the address the connection actually came
	// from. A bot proxying its HTTP through a residential exit shows the proxy IP here, while WebRTC
	// can leak its real IP in the browser layer — the detector cross-checks the two (a proxied-bot tell).
	if ip := clientIP(r); ip != "" {
		out.signals = append(out.signals, signal.Network(out.sessionID, "observed_ip", ip, now))
	}
	// Negotiated HTTP version — a real browser uses HTTP/2 (or h3) to an h2-offering edge; speaking HTTP/1.1
	// here is an older/non-browser stack ("downgrading to h1" is a dead evasion in 2026). A wire fingerprint;
	// shown in the panel. Corroborating, not convicting on its own (corporate proxies can legitimately downgrade).
	httpVer := "http/1.1"
	if r.ProtoMajor == 2 {
		httpVer = "h2"
	}
	out.signals = append(out.signals, signal.Network(out.sessionID, "http_version", httpVer, now))
	// The raw User-Agent the HTTP stack sends on EVERY request — the network-layer client identity string.
	// A real client presents ONE fixed UA for a session's lifetime (the UA is pinned per browser build; a
	// version change requires a restart = a new session). The detector accumulates the distinct UAs under a
	// ks_sid and flags a session that rotates its UA mid-stream — the within-session analog of the JA4/IP
	// rotation tells, and the one that catches a SAME-ENGINE UA rotator (e.g. cycling Chrome build strings)
	// that keeps JA4/h2/OS coherent and so slips past every cross-layer UA rule.
	if ua := r.Header.Get("User-Agent"); ua != "" {
		out.signals = append(out.signals, signal.Network(out.sessionID, "http_user_agent", ua, now))
		// Forward-confirmed reverse DNS for a DECLARED crawler: a UA claiming Googlebot/Bingbot/etc. whose
		// connecting IP does not FCrDNS-confirm to that crawler's official domain is an impersonator. This is
		// the crawlers' OWN documented verification method, so a real crawler always confirms; a transient DNS
		// failure abstains (never convicts a real crawler). Only runs for the rare declared-crawler UA.
		if resolver != nil {
			if suffixes := fingerprint.DeclaredCrawler(ua); suffixes != nil {
				if ip := clientIP(r); ip != "" {
					ctx, cancel := context.WithTimeout(r.Context(), 800*time.Millisecond)
					if fingerprint.VerifyCrawler(ctx, resolver, ip, suffixes) == fingerprint.CrawlerFake {
						out.signals = append(out.signals, signal.Network(out.sessionID, "fake_declared_crawler", true, now))
					}
					cancel()
				}
			}
		}
	}
	// Web Bot Auth (RFC 9421 HTTP Message Signatures, Ed25519): a legitimate agent cryptographically signs its
	// requests. A request that PRESENTS a web-bot-auth signature which FAILS verification against a key we hold
	// (forged / tampered / replayed past its expires window) is a definitive impostor — a real signer always
	// emits a valid, in-window signature for its own key (G25). A VALID signature marks a verified benign agent.
	// An unknown keyid is unjudgeable (we just lack that agent's key), so it never convicts — only a known-key
	// verification FAILURE does, which keeps it FP-safe against legit agents whose directories we don't hold.
	if wba := webbotauth.Verify(reqAuthority(r), r.Header, webbotauth.DefaultKeyDir(), now); wba.Present {
		switch {
		case wba.Valid && wbaReplay != nil && wbaReplay.Replay(wba.KeyID, wba.Nonce, wba.Expires, now):
			// A VALID signature whose nonce was already used in this window: a captured-credential replay.
			// G25's expiry/forgery check passes it (the signature is genuine and in-window); the nonce reuse
			// is the only tell — RFC 9421 nonces are single-use, so a real signer never repeats one. Convicts,
			// and withholds the verified allow-list (the detector's verified_agent gate excludes this rule).
			out.signals = append(out.signals, signal.Network(out.sessionID, "web_bot_auth_nonce_replay", true, now))
		case wba.Valid:
			out.signals = append(out.signals, signal.Network(out.sessionID, "web_bot_auth_verified", true, now))
		case wba.KnownKey:
			out.signals = append(out.signals, signal.Network(out.sessionID, "web_bot_auth_invalid", true, now))
		}
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
	if chUAMobileMismatch(r) {
		out.signals = append(out.signals, signal.Network(out.sessionID, "ch_ua_mobile_mismatch", true, now))
	}
	if chUANoGREASEBrand(r) {
		out.signals = append(out.signals, signal.Network(out.sessionID, "ch_ua_no_grease_brand", true, now))
	}
	return out, nil
}

// chUANoGREASEBrand reports a Chromium Sec-CH-UA brand list that omits the GREASE brand. Every real
// Chromium injects a randomly-punctuated "Not...Brand" entry (RFC-8701-style anti-ossification); a real
// browser brand never contains the word "Brand", so its absence means a hand-assembled, hardcoded
// Sec-CH-UA — a scraper that copied the visible brands and dropped the odd-looking GREASE one.
func chUANoGREASEBrand(r *http.Request) bool {
	v := r.Header.Get("Sec-CH-UA")
	return secCHUABrowser(r) != "" && !strings.Contains(strings.ToLower(v), "brand")
}

// chUAMobileMismatch reports a request whose Sec-CH-UA-Mobile flag disagrees with the form factor its
// User-Agent claims. Chromium sets this hint from the real device, so a scraper faking a mobile UA on a
// desktop stack (Sec-CH-UA-Mobile "?0" under a "...Mobile..." UA) — or the reverse — splits them. Only
// Chromium sends Sec-CH-UA(-Mobile), so the check is scoped to that header's presence.
func chUAMobileMismatch(r *http.Request) bool {
	mobile := r.Header.Get("Sec-CH-UA-Mobile")
	if r.Header.Get("Sec-CH-UA") == "" || mobile == "" {
		return false
	}
	return (mobile == "?1") != strings.Contains(r.Header.Get("User-Agent"), "Mobile")
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

// chromeUAExpectsPQ reports whether the User-Agent claims a Chrome version that ships the post-quantum
// key share on by default (X25519MLKEM768, enabled in Chrome 131). Scoping to >=131 means a genuinely
// older Chrome — which legitimately offers no PQ group — is never flagged by net.tls_pq_keyshare_vs_ua.
func chromeUAExpectsPQ(ua string) bool {
	v := uaChromeMajorVersion(ua)
	if v == "" {
		return false
	}
	n, err := strconv.Atoi(v)
	return err == nil && n >= 131
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

// uaHasKnownH2Order reports whether the UA's engine has a POSITIVELY-identified HTTP/2 pseudo-header order
// in H2Fingerprint.Browser — Chromium (m,a,s,p) and Firefox (m,p,a,s). Safari/WebKit is deliberately
// EXCLUDED: real macOS/iOS Safari's on-wire order is unverified (the m,s,p,a seed is a guess, and real
// Safari emits the generic m,s,a,p which the FP-safe table keeps "unknown"), so an "unknown" h2 under a
// Safari UA is our own blind spot, NOT a contradiction. Convicting it false-positived every real Safari
// (h2_engine_unknown → net.h2_unknown_vs_ua). A non-browser stack faking a Safari UA is still caught by its
// JA4 engine mismatch (net.tls_vs_ua_browser) and the no-JS / Sec-Fetch / Accept-Encoding tells, so excluding
// Safari here loses no grounded coverage while removing the FP. Mirrors the Firefox carve-out in GREASE.
func uaHasKnownH2Order(ua string) bool {
	return strings.Contains(ua, "Chrome/") || strings.Contains(ua, "Edg/") || strings.Contains(ua, "Firefox/")
}

// uaGreasesHandshake reports whether the UA's ENGINE injects GREASE (RFC 8701) into its TLS/QUIC ClientHello
// by default. Chromium and Safari/WebKit do; GECKO/FIREFOX does NOT (security.tls.grease_probability defaults
// to 0). v0.74.31/.32 FP fix, GROUNDED on real geckodriver Firefox 152 + Mullvad 140 + Playwright Firefox: all
// three send a GREASE-free ClientHello (both TLS and QUIC), while every Chromium capture GREASEs — a clean
// engine split. Emitting *_no_grease on a Firefox UA therefore convicted EVERY real Firefox. A non-browser
// stack faking a Firefox UA is still caught by its JA4 engine mismatch (net.tls_vs_ua_browser), so excluding
// Firefox here loses no real coverage; a Chrome/Edge/Safari UA over a GREASE-free handshake remains the tell.
func uaGreasesHandshake(ua string) bool {
	return isModernBrowserUA(ua) && !strings.Contains(ua, "Firefox/")
}

// uaClaimsChromium reports a User-Agent that claims a Chromium engine (Chrome/Edge/Brave) — the only
// family that emits the Sec-CH-UA client-hint group, so it is the only one whose header order can be
// positively classified. Firefox UAs are excluded (Firefox embeds "like Gecko" but never "Firefox/").
func uaClaimsChromium(ua string) bool {
	return (strings.Contains(ua, "Chrome/") || strings.Contains(ua, "Edg/")) && !strings.Contains(ua, "Firefox/")
}

// secFetchMissing reports a request whose User-Agent claims a modern browser but which omits the
// Sec-Fetch metadata headers every such browser sends on real requests. A scripted HTTP client (the
// volumetric-DDoS case) that fakes a browser UA over plain httpx/curl gives itself away here — an
// HTTP-layer tell, independent of the TLS and JS layers.
// reqAuthority is the request's RFC 9421 @authority value: the lower-cased :authority / Host with the default
// https port stripped — what a Web Bot Auth agent signs and what the verifier reconstructs.
func reqAuthority(r *http.Request) string {
	return strings.TrimSuffix(strings.ToLower(r.Host), ":443")
}

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

// uaKernel maps the OS a User-Agent claims to its kernel family — the vocabulary the TCP/IP sniffer
// reports (Android runs the Linux kernel; iOS runs Darwin like macOS). "" when no OS is recognised.
// Compared against the network-stack kernel, it catches an OS spoof a layer below TLS.
func uaKernel(ua string) string {
	switch {
	case strings.Contains(ua, "Windows"):
		return "windows"
	case strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X") ||
		strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		return "darwin"
	case strings.Contains(ua, "Android") || strings.Contains(ua, "Linux") || strings.Contains(ua, "X11"):
		return "linux"
	}
	return ""
}

// ReverseProxy is a transparent TLS edge in front of a backend app.
type ReverseProxy struct {
	backend     *httputil.ReverseProxy
	detectorURL string
	hints       fingerprint.HintTable
	newID       IDFunc
	now         func() time.Time
	client      *http.Client
	synStore    *tcpfp.Store            // source-IP -> TCP/IP kernel family; nil when capture is unavailable
	quic        *QUICCapturer           // source-IP -> QUIC ClientHello; nil when QUIC is not enabled
	altSvc      string                  // Alt-Svc header advertising h3, so browsers attempt QUIC; "" when disabled
	resolver    fingerprint.Resolver    // for FCrDNS crawler verification; nil disables the check
	wbaReplay   *webbotauth.ReplayStore // tracks Web Bot Auth nonces to catch an in-window credential replay
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
		resolver:    net.DefaultResolver,
		wbaReplay:   webbotauth.NewReplayStore(),
	}, nil
}

func (p *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hello, _ := r.Context().Value(helloKey).(*fingerprint.ClientHello)
	h2fp, _ := r.Context().Value(h2Key).(*fingerprint.H2Fingerprint)
	prep, err := prepare(r, hello, h2fp, p.hints, p.newID, p.now(), p.resolver, p.wbaReplay)
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
	// TCP/IP OS coherence: the kernel the client's network stack reveals (from its SYN, captured by the
	// sniffer) versus the kernel its User-Agent claims. A UA spoof cannot change the real TCP stack.
	if uak := uaKernel(r.Header.Get("User-Agent")); uak != "" {
		prep.signals = append(prep.signals, signal.Network(prep.sessionID, "ua_kernel", uak, p.now()))
	}
	if p.synStore != nil {
		if k, ja4t, ok := p.synStore.Get(clientIP(r)); ok {
			if k != "" {
				prep.signals = append(prep.signals, signal.Network(prep.sessionID, "tcp_kernel", k, p.now()))
			}
			if ja4t != "" {
				prep.signals = append(prep.signals, signal.Network(prep.sessionID, "ja4t", ja4t, p.now()))
			}
		}
	}
	// QUIC/HTTP-3 coherence: if the client also attempted QUIC here (drawn by the Alt-Svc advert), the
	// captured QUIC ClientHello is fingerprinted by source IP. A browser GREASEs its QUIC hello; a
	// non-browser QUIC stack under a browser UA does not — quic_no_grease, the QUIC analog of tls_no_grease.
	if p.quic != nil {
		if ch, err := p.quic.FingerprintByIP(clientIP(r)); err == nil && ch != nil {
			prep.signals = append(prep.signals, quicTells(prep.sessionID, ch, r.Header.Get("User-Agent"), p.now())...)
		}
	}
	if p.altSvc != "" {
		w.Header().Set("Alt-Svc", p.altSvc)
	}
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
		// MadeYouReset (CVE-2025-8671): malformed control frames coerce server resets while the client sends
		// no RST_STREAM of its own, so the rapid-reset signal above stays silent — this closes that gap.
		if sc.MadeYouReset() {
			prep.signals = append(prep.signals, signal.Network(prep.sessionID, "h2_madeyoureset", true, p.now()))
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

// ListenAndServe runs the proxy on addr, terminating TLS with loadCert()'s certificate (a real
// browser-trusted keypair in production, else an ephemeral self-signed cert for the lab).
func (p *ReverseProxy) ListenAndServe(addr string) error { // pragma: integration
	cert, err := loadCert()
	if err != nil {
		return err
	}
	// Start the TCP/IP SYN sniffer (best-effort: needs CAP_NET_RAW). If it can't run, the edge serves
	// without tcp_kernel signals rather than failing — the source-IP store simply stays empty.
	p.synStore = tcpfp.NewStore(2 * time.Minute)
	go func() {
		if err := tcpfp.Sniff(p.synStore, make(chan struct{})); err != nil {
			log.Printf("tcp/ip fingerprinting disabled: %v", err)
		}
	}()
	// Start the QUIC capturer on the same port (UDP) and advertise h3 via Alt-Svc, best-effort: it draws
	// and fingerprints client QUIC Initials. If it can't bind, the edge serves h2 without QUIC signals.
	if q, qerr := NewQUICCapturer(addr, cert); qerr == nil {
		p.quic = q
		if _, port, perr := net.SplitHostPort(addr); perr == nil {
			p.altSvc = `h3=":` + port + `"; ma=86400`
		}
	} else {
		log.Printf("quic fingerprinting disabled: %v", qerr)
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

// loadCert returns the edge's TLS certificate. In production set KITSUNE_TLS_CERT + KITSUNE_TLS_KEY to a
// real (Let's Encrypt) PEM keypair — a browser-trusted cert is required for genuine visitors AND for QUIC/
// HTTP-3 (real Chrome refuses QUIC on an untrusted cert). When either env is unset the edge falls back to an
// ephemeral self-signed cert (the lab default; impersonators/tests pass with -ignore-certificate-errors).
func loadCert() (*tls.Certificate, error) { // pragma: integration
	certPath, keyPath := os.Getenv("KITSUNE_TLS_CERT"), os.Getenv("KITSUNE_TLS_KEY")
	if certPath != "" && keyPath != "" {
		c, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load TLS keypair from %s/%s: %w", certPath, keyPath, err)
		}
		log.Printf("edge TLS: loaded keypair from %s", certPath)
		return &c, nil
	}
	log.Printf("edge TLS: KITSUNE_TLS_CERT/KEY unset — using ephemeral self-signed cert (lab mode)")
	return selfSignedCert()
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
		// "edge" is the compose service name the lab reaches the proxy by; covering it lets a
		// hostname-verifying TLS client (a real browser, or impersonators like primp that ignore
		// verify=false) connect without disabling verification, alongside localhost for host runs.
		DNSNames:    []string{"localhost", "edge"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
