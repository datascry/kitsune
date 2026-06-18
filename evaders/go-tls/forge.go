// evaders/go-tls/forge — forge a real-browser TLS ClientHello with uTLS.
// Builds an http.Client whose HTTPS handshakes parrot Chrome/Firefox to beat the JA3/JA4 layer.

package gotls

import (
	"context"
	"net"
	"net/http"

	utls "github.com/refraction-networking/utls"
)

const (
	NAME    = "go-tls"
	VERSION = "0.1.0"
)

// Client returns an http.Client whose TLS handshakes parrot the given browser fingerprint.
// InsecureSkipVerify is set because the lab edge uses a self-signed cert.
func Client(helloID utls.ClientHelloID) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
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
			},
		},
	}
}

// ChromeClient forges the latest Chrome TLS fingerprint.
func ChromeClient() *http.Client { return Client(utls.HelloChrome_Auto) }

// FirefoxClient forges the latest Firefox TLS fingerprint.
func FirefoxClient() *http.Client { return Client(utls.HelloFirefox_Auto) }
