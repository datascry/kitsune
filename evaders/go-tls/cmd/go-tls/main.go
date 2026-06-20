// evaders/go-tls/cmd — drive the forged-TLS evader against the live edge over HTTP/2.
// Sends one faithful Chrome request (UA + browser headers) so the test isolates the uTLS ClientHello.

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	gotls "github.com/datascry/kitsune/evaders/go-tls"
	"github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// quicProbe sends a single naive non-browser QUIC v1 Initial to the edge's UDP port, eliciting the edge's
// QUIC ClientHello capture. Go's crypto/tls does NOT GREASE its hello (unlike Chrome/Safari), and pinning
// the curve to classical X25519 omits the post-quantum X25519MLKEM768 a current Chrome QUIC hello carries —
// so this is a STALE non-browser QUIC template under a Chrome UA, the QUIC analog of the fleet's h2/TLS
// impersonation gap. The handshake fails on the self-signed cert, but the Initial is captured regardless
// (the edge tees Initials before handshake completion). Best-effort: any error is fine, the packet is sent.
func quicProbe(addr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // lab edge self-signed cert
		NextProtos:         []string{"h3"},
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.CurveP256}, // classical only: no PQ key share (stale template)
	}
	conn, err := quic.DialAddr(ctx, addr, cfg, &quic.Config{})
	if err == nil {
		_ = conn.CloseWithError(0, "")
	}
}

// quicMode sends the naive QUIC Initial, then mints a session over h2 from the SAME source IP (the edge
// correlates the captured QUIC hello to the h2 request by IP), and prints the full verdict so the QUIC tells
// (quic_observed / quic_no_grease / quic_no_pq_keyshare) are visible.
func quicMode(target, detector string) {
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		quicProbe(u.Host)
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		log.Fatal(err)
	}
	browserHeaders(req)
	resp, err := gotls.RoundTripH2(context.Background(), utls.HelloChrome_Auto, req)
	if err != nil {
		log.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	var sid string
	for _, c := range resp.Cookies() {
		if c.Name == "ks_sid" {
			sid = c.Value
		}
	}
	if sid == "" {
		log.Fatal("no ks_sid minted")
	}
	vr, err := http.Get(detector + "/verdict/" + sid) //nolint:noctx
	if err != nil {
		log.Fatal(err)
	}
	defer vr.Body.Close()
	var verdict map[string]any
	if err := json.NewDecoder(vr.Body).Decode(&verdict); err != nil {
		log.Fatal(err)
	}
	verdict["mode"] = "go-tls-quic"
	verdict["session_id"] = sid
	out, _ := json.Marshal(verdict) //nolint:errcheck
	fmt.Println("__KS__" + string(out))
}

// browserHeaders makes the request look like a real Chrome navigation, so the only residual tells are
// the layers uTLS does NOT forge: the ClientHello's own fidelity (GREASE / post-quantum key share), the
// HTTP/2 stack (Go's, not Chrome's), the absence of a JS layer, and the kernel. A coherent Linux UA
// keeps tcp_os quiet (the container is Linux).
func browserHeaders(r *http.Request) {
	h := r.Header
	h.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	h.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	h.Set("Accept-Language", "en-US,en;q=0.9")
	h.Set("Sec-Ch-Ua", `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`)
	h.Set("Sec-Ch-Ua-Mobile", "?0")
	h.Set("Sec-Ch-Ua-Platform", `"Linux"`)
	h.Set("Sec-Fetch-Dest", "document")
	h.Set("Sec-Fetch-Mode", "navigate")
	h.Set("Sec-Fetch-Site", "none")
	h.Set("Sec-Fetch-User", "?1")
	h.Set("Upgrade-Insecure-Requests", "1")
}

// rotateJA4 drives several connections under ONE ks_sid, each forging a DIFFERENT TLS engine's
// ClientHello (Chromium / Gecko / WebKit have distinct cipher lists → distinct JA4_b). A real client
// speaks one TLS engine for the session's lifetime, so this within-session rotation is incoherent — the
// red-team move that exercises net.ja4_unstable_within_session. Reports the live detector verdict.
func rotateJA4(target string) {
	detector := os.Getenv("KITSUNE_DETECTOR")
	if detector == "" {
		detector = "http://detector:8080"
	}
	hellos := []struct {
		name string
		id   utls.ClientHelloID
	}{
		{"chrome", utls.HelloChrome_Auto},   // Chromium ciphers
		{"firefox", utls.HelloFirefox_Auto}, // Gecko ciphers (distinct JA4_b)
		{"safari", utls.HelloSafari_Auto},   // WebKit ciphers (distinct JA4_b)
	}
	var sid string
	for i, h := range hellos {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			log.Fatal(err)
		}
		browserHeaders(req)
		if sid != "" {
			req.AddCookie(&http.Cookie{Name: "ks_sid", Value: sid})
		}
		resp, err := gotls.RoundTripH2(context.Background(), h.id, req)
		if err != nil {
			log.Printf("conn %d (%s) error: %v", i, h.name, err)
			continue
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
		if sid == "" {
			for _, c := range resp.Cookies() {
				if c.Name == "ks_sid" {
					sid = c.Value
				}
			}
		}
		log.Printf("conn %d hello=%s -> %s (sid=%s)", i, h.name, resp.Status, sid)
	}
	if sid == "" {
		log.Fatal("no ks_sid minted")
	}
	vr, err := http.Get(detector + "/verdict/" + sid) //nolint:noctx
	if err != nil {
		log.Fatal(err)
	}
	defer vr.Body.Close()
	var verdict map[string]any
	if err := json.NewDecoder(vr.Body).Decode(&verdict); err != nil {
		log.Fatal(err)
	}
	verdict["mode"] = "go-tls-rotate"
	out, _ := json.Marshal(verdict) //nolint:errcheck
	fmt.Println("__KS__" + string(out))
}

// rotateH2 drives several connections under ONE ks_sid, each forging the SAME Chrome ClientHello (one
// JA4_b — the TLS engine never changes) but a DIFFERENT HTTP/2 SETTINGS profile (distinct MaxReadFrameSize
// / MaxHeaderListSize → distinct SETTINGS frame → distinct edge h2 Akamai fingerprint). A real client
// speaks ONE h2 stack for the session's lifetime (its SETTINGS/window/priority are fixed per browser
// build), so this within-session h2 rotation is incoherent in a way the JA4-rotation tell CANNOT see (JA4
// stays constant). The red-team move that exercises net.h2_unstable_within_session.
func rotateH2(target string) {
	detector := os.Getenv("KITSUNE_DETECTOR")
	if detector == "" {
		detector = "http://detector:8080"
	}
	// Three distinct h2 stacks under the SAME uTLS Chrome hello: the SETTINGS values differ → distinct h2 fps.
	profiles := []struct {
		name string
		tr   *http2.Transport
	}{
		{"h2-default", &http2.Transport{}},
		{"h2-bigframe", &http2.Transport{MaxReadFrameSize: 1 << 20, MaxHeaderListSize: 1 << 18}},
		{"h2-smallframe", &http2.Transport{MaxReadFrameSize: 1 << 14, MaxHeaderListSize: 1 << 13}},
	}
	var sid string
	for i, p := range profiles {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			log.Fatal(err)
		}
		browserHeaders(req)
		if sid != "" {
			req.AddCookie(&http.Cookie{Name: "ks_sid", Value: sid})
		}
		resp, err := gotls.RoundTripH2With(context.Background(), utls.HelloChrome_Auto, p.tr, req)
		if err != nil {
			log.Printf("conn %d (%s) error: %v", i, p.name, err)
			continue
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
		if sid == "" {
			for _, c := range resp.Cookies() {
				if c.Name == "ks_sid" {
					sid = c.Value
				}
			}
		}
		log.Printf("conn %d h2=%s -> %s (sid=%s)", i, p.name, resp.Status, sid)
	}
	if sid == "" {
		log.Fatal("no ks_sid minted")
	}
	vr, err := http.Get(detector + "/verdict/" + sid) //nolint:noctx
	if err != nil {
		log.Fatal(err)
	}
	defer vr.Body.Close()
	var verdict map[string]any
	if err := json.NewDecoder(vr.Body).Decode(&verdict); err != nil {
		log.Fatal(err)
	}
	verdict["mode"] = "go-tls-h2-rotate"
	out, _ := json.Marshal(verdict) //nolint:errcheck
	fmt.Println("__KS__" + string(out))
}

func main() {
	target := os.Getenv("KITSUNE_EDGE")
	if target == "" {
		target = "https://localhost:8443/healthz"
	}
	if os.Getenv("KS_ROTATE") == "1" {
		rotateJA4(target)
		return
	}
	if os.Getenv("KS_H2ROTATE") == "1" {
		rotateH2(target)
		return
	}
	if os.Getenv("KS_QUIC") == "1" {
		detector := os.Getenv("KITSUNE_DETECTOR")
		if detector == "" {
			detector = "http://detector:8080"
		}
		quicMode(target, detector)
		return
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		log.Fatal(err)
	}
	browserHeaders(req)
	resp, err := gotls.RoundTripH2(context.Background(), utls.HelloChrome_Auto, req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	log.Printf("go-tls (chrome fingerprint, h2) -> %s : %s [%d bytes]", target, resp.Status, len(body))
	// Print the correlation id (from the edge's Set-Cookie) to stdout for inspection.
	for _, c := range resp.Cookies() {
		if c.Name == "ks_sid" {
			fmt.Println(c.Value)
		}
	}
}
