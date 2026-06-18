// edge/proxy/quiccapture_test — a real quic-go client connects; the capturer must fingerprint its hello.
// Self-validating: quic-go (trusted) produces the QUIC handshake, QUICCapturer recovers the ClientHello.

package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestQUICCapturerFingerprintsClientHello(t *testing.T) {
	cert, err := selfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	cap, err := NewQUICCapturer("127.0.0.1:0", cert)
	if err != nil {
		t.Fatal(err)
	}
	defer cap.Close()

	cliConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cliConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, cliConn, cap.Addr(), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		NextProtos:         []string{"h3"},
		ServerName:         "edge",
	}, &quic.Config{})
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	// The handshake completed, so the client's Initial(s) were tee'd from cliConn's local address.
	src := cliConn.LocalAddr().String()
	var ch interface {
		HasGREASE() bool
	}
	// Small retry: the capture happens on the listener's read goroutine.
	deadline := time.Now().Add(2 * time.Second)
	for {
		got, ferr := cap.Fingerprint(src)
		if ferr == nil {
			if got.Transport != "q" {
				t.Errorf("transport = %q, want q", got.Transport)
			}
			if len(got.CipherSuites) == 0 {
				t.Error("no cipher suites recovered from the QUIC ClientHello")
			}
			ch = got
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no QUIC fingerprint captured for %s: %v", src, ferr)
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = ch
}
