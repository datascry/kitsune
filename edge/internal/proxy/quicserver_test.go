// edge/proxy/quicserver_test — a real http3 client requests through QUICServer to a stub backend.
// Proves the per-connection path: the request's QUIC fingerprint is attributed to its ks_sid by DCID.

package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
	"github.com/datascry/kitsune/edge/internal/session"
	"github.com/datascry/kitsune/edge/internal/signal"
)

func TestQUICServerAttributesFingerprintByDCID(t *testing.T) {
	cert, err := selfSignedCert()
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var got []signal.Signal
	forward := func(sigs []signal.Signal) {
		mu.Lock()
		got = append(got, sigs...)
		mu.Unlock()
	}
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})

	qs, err := NewQUICServer("127.0.0.1:0", cert, fingerprint.HintTable{}, session.NewID, time.Now, forward, backend)
	if err != nil {
		t.Fatal(err)
	}
	defer qs.Close()

	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, ServerName: "edge"}, //nolint:gosec
	}
	defer rt.Close()

	const chromeUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	req, err := http.NewRequest(http.MethodGet, "https://"+qs.Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", chromeUA)
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: "test-sid"})

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("h3 round trip: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("backend response = %d %q; want 200 ok", resp.StatusCode, body)
	}

	// The handler forwards BEFORE writing the response, so by now the signals are recorded. quic_observed is
	// emitted only when fingerprintByDCID returned a hello — its presence proves the full per-connection path
	// (Initial captured → DCID bound at connection start → request attributed by DCID), under the request's
	// ks_sid (read from the cookie, not matched by source IP).
	mu.Lock()
	defer mu.Unlock()
	var observed bool
	for _, s := range got {
		if s.Kind == "quic_observed" {
			observed = true
			if s.SessionID != "test-sid" {
				t.Errorf("quic_observed session = %q, want test-sid (the request's ks_sid)", s.SessionID)
			}
		}
	}
	if !observed {
		t.Fatalf("no quic_observed signal — the request was not attributed to its QUIC fingerprint by DCID (got %d signals)", len(got))
	}
}
