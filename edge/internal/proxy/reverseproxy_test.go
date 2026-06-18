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
	prep, err := prepare(req(t, ""), helloFixture(t), fingerprint.HintTable{}, fixedID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if prep.sessionID != "fixed-session" || prep.setCookie == nil {
		t.Errorf("session=%s setCookie=%v", prep.sessionID, prep.setCookie)
	}
	if len(prep.signals) != 2 {
		t.Errorf("want ja3+ja4 signals, got %d", len(prep.signals))
	}
}

func TestPrepareReusesCookie(t *testing.T) {
	prep, err := prepare(req(t, "abc"), helloFixture(t), fingerprint.HintTable{}, fixedID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if prep.sessionID != "abc" || prep.setCookie != nil {
		t.Errorf("session=%s setCookie=%v", prep.sessionID, prep.setCookie)
	}
}

func TestPrepareNilHello(t *testing.T) {
	prep, err := prepare(req(t, "abc"), nil, fingerprint.HintTable{}, fixedID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(prep.signals) != 0 {
		t.Errorf("expected no signals without a ClientHello, got %d", len(prep.signals))
	}
}

func TestPrepareIDFailure(t *testing.T) {
	if _, err := prepare(req(t, ""), nil, fingerprint.HintTable{}, failID, time.Now()); err == nil {
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
