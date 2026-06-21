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

// TestQUICTeeTTLExpiresStaleInitials guards the cross-attribution fix: a captured Initial older than the TTL
// must NOT be returned (and is purged), so a later session that recycled the source IP cannot inherit a stale
// hello from a since-departed client — the root cause of the quic_no_grease false positive (see roadmap).
func TestQUICTeeTTLExpiresStaleInitials(t *testing.T) {
	clk := time.Now()
	tee := &quicInitialTee{initials: map[string]*teeEntry{}, now: func() time.Time { return clk }}
	// A Chrome-class GREASE-less Initial-ish blob is irrelevant here — take() works on raw fragments by age.
	tee.initials["10.0.0.7:51000"] = &teeEntry{pkts: [][]byte{{0x01, 0x02}}, seen: clk}

	// Fresh: within the TTL, take() returns it.
	if got := tee.take(func(addr string, _ *teeEntry) bool { return addr == "10.0.0.7:51000" }); got == nil {
		t.Fatal("fresh entry within TTL should be returned")
	}
	// Advance past the TTL: the same entry is now stale → not returned, and purged from the map.
	clk = clk.Add(quicTeeTTL + time.Second)
	if got := tee.take(func(addr string, _ *teeEntry) bool { return addr == "10.0.0.7:51000" }); got != nil {
		t.Error("stale entry past TTL must not be returned (cross-attribution to a recycled IP)")
	}
	if _, ok := tee.initials["10.0.0.7:51000"]; ok {
		t.Error("stale entry must be purged from the tee (bounds memory)")
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
	// Firefox UA → gated off (v0.74.32): Gecko does not GREASE its QUIC hello either, so emitting this on a
	// real Firefox is a false positive (uaGreasesHandshake excludes Firefox).
	const firefoxUA = "Mozilla/5.0 (X11; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0"
	if kinds(quicTells("s", plain, firefoxUA, time.Now()))["quic_no_grease"] {
		t.Error("Firefox UA must not fire quic_no_grease (Gecko does not GREASE)")
	}

	// QUIC PQ key-share tell: a Chrome >=131 UA whose QUIC hello lacks the MLKEM group fires it.
	const chrome131 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	noPQ := &fingerprint.ClientHello{CipherSuites: []uint16{0x1301}, SupportedGroups: []uint16{0x001d, 0x0017}}
	withPQ := &fingerprint.ClientHello{CipherSuites: []uint16{0x1301}, SupportedGroups: []uint16{0x11ec, 0x001d}}
	if !kinds(quicTells("s", noPQ, chrome131, time.Now()))["quic_no_pq_keyshare"] {
		t.Error("Chrome/131 + QUIC hello without MLKEM should fire quic_no_pq_keyshare")
	}
	if kinds(quicTells("s", withPQ, chrome131, time.Now()))["quic_no_pq_keyshare"] {
		t.Error("a QUIC hello with X25519MLKEM768 must not fire quic_no_pq_keyshare")
	}
}

// TestFingerprintByDCID drives a real quic-go handshake and confirms the captured Initial can be retrieved
// by its client-chosen Destination Connection ID — the per-connection attribution primitive (ADR-0005),
// the path that replaces source-IP matching once the edge serves H3 and links the Initial to a ks_sid.
func TestFingerprintByDCID(t *testing.T) {
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

	// Wait for the capture (happens on the listener read goroutine), then read the recorded DCID.
	src := cliConn.LocalAddr().String()
	var dcid string
	deadline := time.Now().Add(2 * time.Second)
	for {
		cap.tee.mu.Lock()
		if e := cap.tee.initials[src]; e != nil {
			dcid = e.dcid
		}
		cap.tee.mu.Unlock()
		if dcid != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no Initial with a DCID captured")
		}
		time.Sleep(20 * time.Millisecond)
	}

	got, err := cap.FingerprintByDCID([]byte(dcid))
	if err != nil {
		t.Fatalf("FingerprintByDCID(captured) error: %v", err)
	}
	if got.Transport != "q" {
		t.Errorf("transport = %q, want q", got.Transport)
	}
	// A DCID nothing was captured for must not mis-attribute.
	if _, err := cap.FingerprintByDCID([]byte("nonexistent-dcid")); err == nil {
		t.Error("FingerprintByDCID(unknown) should error, not mis-attribute")
	}
}
