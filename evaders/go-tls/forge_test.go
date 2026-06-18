// evaders/go-tls/forge_test — prove the forged ClientHello reaches a server as a browser.
// Spins a TLS server, captures the offered ciphers, and asserts Chrome/Firefox differ + are browser-like.

package gotls

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// tlsServerCapturing starts an HTTPS test server that records each ClientHello's offered ciphers.
func tlsServerCapturing(t *testing.T) (*httptest.Server, func() []uint16) {
	t.Helper()
	var mu sync.Mutex
	var ciphers []uint16
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			ciphers = append([]uint16(nil), chi.CipherSuites...)
			mu.Unlock()
			return nil, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, func() []uint16 { mu.Lock(); defer mu.Unlock(); return ciphers }
}

func TestForgedChromeReachesServer(t *testing.T) {
	srv, offered := tlsServerCapturing(t)

	client := ChromeClient()
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("forged request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d", resp.StatusCode)
	}
	// A real browser offers many cipher suites; the stdlib default would offer far fewer.
	if got := len(offered()); got < 10 {
		t.Errorf("expected a browser-like cipher list, got %d ciphers", got)
	}
}

func TestChromeAndFirefoxDiffer(t *testing.T) {
	fingerprints := map[string][]uint16{}
	for name, c := range map[string]*http.Client{
		"chrome":  Client(utls.HelloChrome_Auto),
		"firefox": Client(utls.HelloFirefox_Auto),
	} {
		srv, offered := tlsServerCapturing(t)
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		resp.Body.Close()
		fingerprints[name] = offered()
	}
	if equalU16(fingerprints["chrome"], fingerprints["firefox"]) {
		t.Error("chrome and firefox forged the same cipher list")
	}
}

func equalU16(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
