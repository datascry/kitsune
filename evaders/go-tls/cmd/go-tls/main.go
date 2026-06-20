// evaders/go-tls/cmd — drive the forged-TLS evader against the live edge over HTTP/2.
// Sends one faithful Chrome request (UA + browser headers) so the test isolates the uTLS ClientHello.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	gotls "github.com/datascry/kitsune/evaders/go-tls"
	utls "github.com/refraction-networking/utls"
)

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

func main() {
	target := os.Getenv("KITSUNE_EDGE")
	if target == "" {
		target = "https://localhost:8443/healthz"
	}
	if os.Getenv("KS_ROTATE") == "1" {
		rotateJA4(target)
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
