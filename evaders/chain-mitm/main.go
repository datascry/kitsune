// evaders/chain-mitm/main — a uTLS MITM front that forges a browser TLS+H2 handshake to the edge.
// A real browser proxies through it, so the edge sees a forged network layer + a real JS runtime (the chain).

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// helloID maps KS_HELLO to a uTLS fingerprint. This is the "front" half of the chain — the network engine
// the edge sees, INDEPENDENT of whatever browser runs behind. Mismatch it against the browser to exercise
// the engine-coherence seam (a Firefox front under a Chromium browser trips net.tls_vs_ua_browser).
func helloID() utls.ClientHelloID {
	switch env("KS_HELLO", "chrome") {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	default:
		return utls.HelloChrome_Auto
	}
}

// dialUTLS opens a uTLS-forged TLS connection to addr parroting the configured browser ClientHello. The edge
// uses a self-signed cert, so verification is skipped. This is the forged network layer of the chain.
func dialUTLS(ctx context.Context, addr string) (net.Conn, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	cfg := &utls.Config{ServerName: host, InsecureSkipVerify: true} //nolint:gosec
	uconn := utls.UClient(raw, cfg, helloID())
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return uconn, nil
}

// utlsH2Transport is an HTTP/2 transport whose TLS handshakes are forged with uTLS. It POOLS connections
// (one h2 conn to the edge, reused for all the browser's requests) exactly as a real browser does, so the
// edge sees one forged ClientHello + one h2 session — not a fresh handshake per request. uTLS forges only
// the ClientHello; the HTTP/2 SETTINGS/window/priority + pseudo-header order are Go's, so a Chrome-TLS
// front over a Go-H2 stack is the classic integration seam (net.h2_* vs the browser UA).
func utlsH2Transport() *http2.Transport {
	return &http2.Transport{
		DialTLSContext: func(ctx context.Context, _ string, addr string, _ *tls.Config) (net.Conn, error) {
			return dialUTLS(ctx, addr)
		},
	}
}

func selfSignedCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kitsune-chain-front"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"localhost", "chain-mitm", "front"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func main() {
	edgeURL := env("KITSUNE_EDGE", "https://edge:8443")
	addr := env("FRONT_ADDR", "0.0.0.0:8444")
	target, err := url.Parse(edgeURL)
	if err != nil {
		log.Fatalf("bad KITSUNE_EDGE: %v", err)
	}

	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = utlsH2Transport()
	baseDirector := rp.Director
	rp.Director = func(r *http.Request) {
		baseDirector(r)
		r.Host = target.Host            // present the edge authority, not the front's, so the request looks direct
		r.Header.Del("X-Forwarded-For") // a real browser never sends this — drop the proxy artifact
	}
	rp.ErrorLog = log.New(os.Stderr, "chain-front ", log.LstdFlags)

	srv := &http.Server{
		Addr:    addr,
		Handler: rp,
		// Offer h2 on the browser side so the real browser generates h2-native requests (the headers +
		// order the edge fingerprints); the front re-serializes them over the forged uTLS+h2 link.
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{selfSignedCert()}, NextProtos: []string{"h2", "http/1.1"}},
		ReadHeaderTimeout: 15 * time.Second,
	}
	log.Printf("chain-mitm front on %s -> %s (hello=%s, h2=go)", addr, edgeURL, env("KS_HELLO", "chrome"))
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
