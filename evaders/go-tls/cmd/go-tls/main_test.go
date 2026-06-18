// evaders/go-tls/cmd/main_test — assert the forged request carries a faithful Chrome header set.
// A real impersonator pairs the uTLS handshake with browser headers; missing ones are their own tells.

package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestBrowserHeaders(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "https://edge/", nil)
	if err != nil {
		t.Fatal(err)
	}
	browserHeaders(r)
	if ua := r.Header.Get("User-Agent"); !strings.Contains(ua, "Chrome/131") {
		t.Errorf("User-Agent is not a current Chrome: %q", ua)
	}
	// Must carry the GREASE brand and the modern Accept-Encoding, else net.* HTTP tells fire on their own.
	if !strings.Contains(r.Header.Get("Sec-Ch-Ua"), "Brand") {
		t.Error("Sec-CH-UA omits the GREASE brand")
	}
	if ae := r.Header.Get("Accept-Encoding"); !strings.Contains(ae, "br") || !strings.Contains(ae, "zstd") {
		t.Errorf("Accept-Encoding is not browser-like: %q", ae)
	}
	if r.Header.Get("Sec-Fetch-Mode") == "" {
		t.Error("missing Sec-Fetch-* metadata")
	}
}
