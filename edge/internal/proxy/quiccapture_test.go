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

	"github.com/datascry/kitsune/edge/internal/fingerprint"
	"github.com/datascry/kitsune/edge/internal/signal"
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

	// FingerprintByIP must find the same hello matching on IP alone (the request arrives over TCP from
	// the same IP on a different port).
	host, _, _ := net.SplitHostPort(src)
	if byIP, err := cap.FingerprintByIP(host); err != nil || byIP == nil {
		t.Errorf("FingerprintByIP(%s) = %v, %v; want a hello", host, byIP, err)
	}
}

func TestQUICTells(t *testing.T) {
	const chromeUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	greased := &fingerprint.ClientHello{CipherSuites: []uint16{0x0a0a, 0x1301}} // 0x0a0a is a GREASE value
	plain := &fingerprint.ClientHello{CipherSuites: []uint16{0x1301, 0xc02b}}   // no GREASE

	kinds := func(sigs []signal.Signal) map[string]bool {
		m := map[string]bool{}
		for _, s := range sigs {
			m[s.Kind] = true
		}
		return m
	}
	// A browser UA over a non-GREASE QUIC hello → the tell fires (plus the observational marker).
	k := kinds(quicTells("s", plain, chromeUA, time.Now()))
	if !k["quic_observed"] || !k["quic_no_grease"] {
		t.Errorf("chrome UA + non-GREASE QUIC hello: got %v, want quic_observed + quic_no_grease", k)
	}
	// A browser whose QUIC hello GREASEs (the real case) → no tell.
	if kinds(quicTells("s", greased, chromeUA, time.Now()))["quic_no_grease"] {
		t.Error("GREASE'd QUIC hello must not fire quic_no_grease")
	}
	// Non-browser UA → gated off (caught by other tells, not this one).
	if kinds(quicTells("s", plain, "curl/8.0", time.Now()))["quic_no_grease"] {
		t.Error("non-browser UA must not fire quic_no_grease")
	}
}
