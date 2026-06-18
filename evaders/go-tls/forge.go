// evaders/go-tls/forge — forge a real-browser TLS ClientHello with uTLS.
// Builds an http.Client whose HTTPS handshakes parrot Chrome/Firefox to beat the JA3/JA4 layer.

package gotls

import (
	"context"
	"net"
	"net/http"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	NAME    = "go-tls"
	VERSION = "0.1.0"
)

// dialUTLS opens a TCP connection and performs a uTLS handshake parroting helloID's browser
// fingerprint. InsecureSkipVerify is set because the lab edge uses a self-signed cert.
func dialUTLS(ctx context.Context, addr string, helloID utls.ClientHelloID) (net.Conn, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		raw.Close()
		return nil, err
	}
	cfg := &utls.Config{ServerName: host, InsecureSkipVerify: true} //nolint:gosec
	uconn := utls.UClient(raw, cfg, helloID)
	if err := uconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return uconn, nil
}

// Client returns an http.Client whose TLS handshakes parrot the given browser fingerprint (HTTP/1.1
// transport — used to inspect the forged ClientHello at the TLS layer).
func Client(helloID utls.ClientHelloID) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialUTLS(ctx, addr, helloID)
			},
		},
	}
}

// RoundTripH2 performs req over an HTTP/2 connection whose TLS handshake is forged with helloID — the
// transport a real Chrome speaks, and what the h2-only edge requires. uTLS forges the ClientHello but not
// the HTTP/2 layer: the h2 SETTINGS/window are Go's, so the edge still sees that cross-layer incoherence
// (a Chrome TLS fingerprint under a Go HTTP/2 stack). Uses NewClientConn to drive h2 directly over the
// uTLS conn, sidestepping the uTLS/net-http2 ConnectionState type mismatch.
func RoundTripH2(ctx context.Context, helloID utls.ClientHelloID, req *http.Request) (*http.Response, error) {
	addr := req.URL.Host
	if req.URL.Port() == "" {
		addr = net.JoinHostPort(req.URL.Hostname(), "443")
	}
	conn, err := dialUTLS(ctx, addr, helloID)
	if err != nil {
		return nil, err
	}
	cc, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return cc.RoundTrip(req)
}

// ChromeClient forges the latest Chrome TLS fingerprint (HTTP/1.1).
func ChromeClient() *http.Client { return Client(utls.HelloChrome_Auto) }

// FirefoxClient forges the latest Firefox TLS fingerprint (HTTP/1.1).
func FirefoxClient() *http.Client { return Client(utls.HelloFirefox_Auto) }
