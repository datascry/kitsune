// edge/proxy/handler_test — HTTP-level tests for the edge handler.
// Covers healthz, fingerprinting, error paths, session reuse, and detector forwarding.

package proxy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
)

func fixedID() (string, error) { return "fixed-session", nil }
func failID() (string, error)  { return "", errors.New("boom") }
func fixedNow() time.Time      { return time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC) }

// minimalClientHello is a valid extension-less ClientHello record (TLS 1.2 legacy).
func minimalClientHello() []byte {
	chBody := []byte{0x03, 0x03}
	chBody = append(chBody, make([]byte, 32)...)    // random
	chBody = append(chBody, 0x00)                   // session id len
	chBody = append(chBody, 0x00, 0x02, 0x13, 0x01) // ciphers: len 2 + 0x1301
	chBody = append(chBody, 0x01, 0x00)             // compression
	hs := append([]byte{0x01, 0x00, byte(len(chBody) >> 8), byte(len(chBody))}, chBody...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func newHandler(detectorURL string) *Handler {
	return New(detectorURL, fingerprint.HintTable{}, fixedID, fixedNow)
}

func TestHealthz(t *testing.T) {
	rr := httptest.NewRecorder()
	newHandler("").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
}

func postFingerprint(t *testing.T, h *Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(body)))
	return rr
}

func TestFingerprintMintsSession(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString(minimalClientHello())
	rr := postFingerprint(t, newHandler(""), `{"client_hello_b64":"`+b64+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body)
	}
	var resp fpResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.SessionID != "fixed-session" {
		t.Errorf("session=%s", resp.SessionID)
	}
	if len(resp.Signals) != 2 {
		t.Errorf("want ja3+ja4, got %d signals", len(resp.Signals))
	}
}

func TestFingerprintKeepsProvidedSession(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString(minimalClientHello())
	rr := postFingerprint(t, newHandler(""), `{"client_hello_b64":"`+b64+`","session_id":"abc"}`)
	var resp fpResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.SessionID != "abc" {
		t.Errorf("session=%s", resp.SessionID)
	}
}

func TestFingerprintErrors(t *testing.T) {
	cases := map[string]struct {
		body string
		want int
	}{
		"bad-json":   {`not json`, http.StatusBadRequest},
		"bad-base64": {`{"client_hello_b64":"!!!"}`, http.StatusBadRequest},
		"bad-hello":  {`{"client_hello_b64":"AAAA"}`, http.StatusUnprocessableEntity},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if rr := postFingerprint(t, newHandler(""), tc.body); rr.Code != tc.want {
				t.Errorf("status %d want %d", rr.Code, tc.want)
			}
		})
	}
}

func TestFingerprintIDFailure(t *testing.T) {
	h := New("", fingerprint.HintTable{}, failID, fixedNow)
	b64 := base64.StdEncoding.EncodeToString(minimalClientHello())
	if rr := postFingerprint(t, h, `{"client_hello_b64":"`+b64+`"}`); rr.Code != http.StatusInternalServerError {
		t.Errorf("status %d", rr.Code)
	}
}

func TestForwardsToDetector(t *testing.T) {
	got := make(chan []byte, 1)
	detector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer detector.Close()

	b64 := base64.StdEncoding.EncodeToString(minimalClientHello())
	postFingerprint(t, newHandler(detector.URL), `{"client_hello_b64":"`+b64+`"}`)

	select {
	case body := <-got:
		if !strings.Contains(string(body), `"layer":"network"`) {
			t.Errorf("forwarded body missing network signal: %s", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("detector did not receive forwarded signals")
	}
}
