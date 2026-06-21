// edge/fingerprint/quic_test — validate the QUIC Initial decryptor against a real quic-go client packet.
// quic-go (trusted reference) emits a genuine Initial; ParseQUICInitial must recover its ClientHello.

package fingerprint

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestParseQUICInitial(t *testing.T) {
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	captured := make(chan []byte, 16)
	go func() {
		for {
			buf := make([]byte, 1600)
			n, _, rerr := srv.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			captured <- buf[:n]
		}
	}()

	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// Dial never completes (the server never replies); it sends client Initial packet(s), which we
	// capture. A hello with post-quantum key shares spans multiple Initials, so we collect several.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	go quic.Dial(ctx, cli, srv.LocalAddr(), &tls.Config{ //nolint:errcheck
		InsecureSkipVerify: true, //nolint:gosec
		NextProtos:         []string{"h3"},
		ServerName:         "example.com",
	}, &quic.Config{})

	var pkts [][]byte
	deadline := time.After(2 * time.Second)
	for len(pkts) < 8 {
		select {
		case p := <-captured:
			pkts = append(pkts, p)
		case <-deadline:
			goto done
		}
		if len(pkts) >= 2 {
			// brief settle for the fragment tail
			select {
			case p := <-captured:
				pkts = append(pkts, p)
			case <-time.After(150 * time.Millisecond):
			}
		}
	}
done:
	if len(pkts) == 0 {
		t.Fatal("no QUIC Initial captured")
	}

	ch, err := ParseQUICInitials(pkts)
	if err != nil {
		t.Fatalf("ParseQUICInitials (%d pkts): %v", len(pkts), err)
	}
	if ch.Transport != "q" {
		t.Errorf("transport = %q, want q", ch.Transport)
	}
	if len(ch.CipherSuites) == 0 {
		t.Error("recovered no cipher suites from the QUIC ClientHello")
	}
	hasH3 := false
	for _, a := range ch.ALPN {
		if a == "h3" {
			hasH3 = true
		}
	}
	if !hasH3 {
		t.Errorf("ALPN %v does not contain h3", ch.ALPN)
	}
	// quic-go builds its ClientHello with Go's crypto/tls, which does not inject GREASE (only browsers
	// do) — so this recovered hello must NOT GREASE. (A real browser's QUIC hello would; that contrast is
	// exactly what the eventual net.tls_grease_vs_ua check exploits over QUIC.)
	if ch.HasGREASE() {
		t.Error("quic-go/Go-TLS hello unexpectedly GREASEd")
	}
	if len(ch.SupportedGroups) == 0 {
		t.Error("recovered no supported groups (key shares) from the QUIC ClientHello")
	}
}

func TestParseQUICInitialRejectsNonQUIC(t *testing.T) {
	if _, err := ParseQUICInitial([]byte{0x16, 0x03, 0x01, 0x00}); err == nil {
		t.Error("a TLS record is not a QUIC Initial; expected an error")
	}
	if _, err := ParseQUICInitial(nil); err == nil {
		t.Error("empty input should error")
	}
}

// TestInitialDCID pins the cleartext Destination Connection ID extraction (the ADR-0005 per-connection
// attribution key) without decryption — including the rejections that keep it from mis-keying garbage.
func TestInitialDCID(t *testing.T) {
	// Well-formed v1 Initial long header: 0xc0 (long+fixed, type 00), version 1, dcidLen 4, then the DCID.
	good := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0x00}
	dcid, ok := InitialDCID(good)
	if !ok || string(dcid) != string([]byte{0xaa, 0xbb, 0xcc, 0xdd}) {
		t.Fatalf("InitialDCID(good) = %x, %v; want aabbccdd, true", dcid, ok)
	}

	cases := map[string][]byte{
		"short-header (form bit clear)": {0x40, 0x00, 0x00, 0x00, 0x01, 0x04, 0xaa, 0xbb, 0xcc, 0xdd},
		"wrong version":                 {0xc0, 0x00, 0x00, 0x00, 0x02, 0x04, 0xaa, 0xbb, 0xcc, 0xdd},
		"non-initial packet type":       {0xf0, 0x00, 0x00, 0x00, 0x01, 0x04, 0xaa, 0xbb, 0xcc, 0xdd},
		"too short":                     {0xc0, 0x00, 0x00},
		"zero-length dcid":              {0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x41, 0x00},
		"dcid len exceeds packet":       {0xc0, 0x00, 0x00, 0x00, 0x01, 0x14, 0xaa, 0xbb},
	}
	for name, pkt := range cases {
		if _, ok := InitialDCID(pkt); ok {
			t.Errorf("InitialDCID(%s) returned ok; want false", name)
		}
	}
}
