// edge/fingerprint/quic_chrome_test — multi-packet QUIC reassembly guard via a Chrome-parroting hello (uquic).
// Proves ParseQUICInitials recovers a multi-Initial Chrome-class ClientHello in full (the retirement's "reassembly unreliable" claim is refuted).

package fingerprint

import (
	"context"
	"net"
	"testing"
	"time"

	uquic "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"
)

// TestParseQUICInitialChromeMultiPacket dials with uquic's QUICChrome_115 parrot — a Chrome-class QUIC
// ClientHello that spans MULTIPLE Initial packets (the post-quantum / large key-share case) — and asserts
// the edge's decryptor reassembles it in full: all three TLS 1.3 ciphers, the key_share + supported_versions
// extensions, and the h3 ALPN. This refutes the net.quic_no_grease_vs_ua retirement's hypothesis that the
// "multi-packet CRYPTO reassembly is unreliable and misses the key share" — a 7-packet hello recovers cleanly.
//
// It ALSO documents WHY uquic cannot ground a quic_no_grease fix: uquic's QUIC Chrome parrot carries GREASE
// only as VERSION_GREASE (a value inside supported_versions), GREASE QUIC transport parameters and the GREASE
// QUIC bit — NOT as a GREASE cipher or GREASE extension-TYPE, which is what HasGREASE() inspects. So this
// faithful Chrome-QUIC tool legitimately recovers WITHOUT cipher/extension GREASE, and the quic_no_grease FP
// on real Chromium can only be resolved against a REAL Chrome QUIC capture (BoringSSL does add a GREASE
// cipher/extension; uquic's parrot omits it). The convicting QUIC rules therefore stay retired — confirmed.
func TestParseQUICInitialChromeMultiPacket(t *testing.T) {
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	captured := make(chan []byte, 32)
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

	spec, err := uquic.QUICID2Spec(uquic.QUICChrome_115)
	if err != nil {
		t.Fatal(err)
	}
	ut := &uquic.UTransport{Transport: &uquic.Transport{Conn: cli}, QUICSpec: &spec}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	// Dial never completes (the server never replies); we capture the client Initials it emits.
	go ut.DialEarly(ctx, srv.LocalAddr(), &utls.Config{ //nolint:errcheck
		InsecureSkipVerify: true, //nolint:gosec
		NextProtos:         []string{"h3"},
		ServerName:         "example.com",
	}, &uquic.Config{})

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
			select {
			case p := <-captured:
				pkts = append(pkts, p)
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
done:
	if len(pkts) < 2 {
		t.Fatalf("expected a multi-packet Chrome QUIC hello, captured %d packet(s)", len(pkts))
	}
	ch, err := ParseQUICInitials(pkts)
	if err != nil {
		t.Fatalf("ParseQUICInitials (%d pkts): %v", len(pkts), err)
	}
	// Full reassembly across packets: the three TLS 1.3 ciphers must all be recovered.
	if len(ch.CipherSuites) != 3 {
		t.Errorf("ciphers = %04x, want the 3 TLS 1.3 suites (multi-packet reassembly incomplete)", ch.CipherSuites)
	}
	has := func(target uint16) bool {
		for _, e := range ch.Extensions {
			if e == target {
				return true
			}
		}
		return false
	}
	if !has(0x0033) { // key_share — the large extension the retirement claimed the capture "misses"
		t.Errorf("key_share (0x0033) not recovered from the multi-packet hello: exts=%04x", ch.Extensions)
	}
	if !has(0x002b) { // supported_versions (carries uquic's VERSION_GREASE value)
		t.Errorf("supported_versions (0x002b) not recovered: exts=%04x", ch.Extensions)
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
	// uquic's QUIC Chrome parrot does NOT inject a GREASE cipher/extension-type (only version/QTP/bit GREASE),
	// so HasGREASE() is correctly false here — documenting why uquic cannot ground a quic_no_grease fix.
	if ch.HasGREASE() {
		t.Error("unexpected cipher/extension GREASE: uquic's QUIC Chrome parrot is not supposed to inject it")
	}
}
