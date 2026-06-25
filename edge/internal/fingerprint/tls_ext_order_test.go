// edge/fingerprint/tls_ext_order_test — grounds the within-session static-ext-order tell's two premises.
// Real Chrome (HelloChrome_131, rebuilt per hello) PERMUTES its extension order; a reused pinned spec does NOT.

package fingerprint

import (
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// extOrderOf builds a uTLS ClientHello in memory (no network) and returns the edge's ExtOrder() of it
// (GREASE normalized to "g"). mk receives a throwaway net.Conn (never used for IO — BuildHandshakeState
// marshals the hello without a handshake) and returns the configured UConn.
func extOrderOf(t *testing.T, mk func(conn net.Conn) *utls.UConn) (*ClientHello, string) {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	u := mk(c1)
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}
	ch, err := ParseClientHelloHandshake(u.HandshakeState.Hello.Raw, "t")
	if err != nil {
		t.Fatalf("ParseClientHelloHandshake: %v", err)
	}
	return ch, ch.ExtOrder()
}

// TestRealChromePermutesExtensionOrder grounds the FP-SAFE NEGATIVE of net.tls_ext_order_static_within_session:
// a real Chrome (BoringSSL extension permutation, replicated by uTLS HelloChrome_131) emits a DIFFERENT
// extension order on every ClientHello, so a within-session "order is identical across connections" rule can
// never fire on real Chrome — there is no static order to catch.
func TestRealChromePermutesExtensionOrder(t *testing.T) {
	cfg := &utls.Config{ServerName: "example.com", InsecureSkipVerify: true} //nolint:gosec
	_, o1 := extOrderOf(t, func(c net.Conn) *utls.UConn { return utls.UClient(c, cfg, utls.HelloChrome_131) })
	_, o2 := extOrderOf(t, func(c net.Conn) *utls.UConn { return utls.UClient(c, cfg, utls.HelloChrome_131) })
	_, o3 := extOrderOf(t, func(c net.Conn) *utls.UConn { return utls.UClient(c, cfg, utls.HelloChrome_131) })
	if o1 == o2 && o2 == o3 {
		t.Errorf("HelloChrome_131 must PERMUTE its extension order per hello (the FP-safety premise); got an "+
			"identical order across 3 hellos: %s", o1)
	}
}

// TestPinnedSpecStaticExtensionOrder grounds the POSITIVE of net.tls_ext_order_static_within_session: a
// faithful anti-detect tool that pins ONE Chrome hello and replays it emits a byte-identical extension order
// on every connection — a constant order under a Chrome UA, which a real Chrome (above) never produces. Here
// a reused CURRENT-Chrome spec (HelloChrome_131) still GREASEs and carries a PQ key share, so it passes
// net.tls_grease_vs_ua and net.tls_pq_keyshare_vs_ua — proving the static order is the ONLY residual tell even
// for a current hello, the gap JA4 (which sorts extensions) leaves open. (The live go-tls KS_STATICEXT evader
// pins a non-shuffling HelloChrome_102 to achieve the same static order without per-connection reuse.)
func TestPinnedSpecStaticExtensionOrder(t *testing.T) {
	cfg := &utls.Config{ServerName: "example.com", InsecureSkipVerify: true} //nolint:gosec
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_131)
	if err != nil {
		t.Fatal(err)
	}
	pin := func(c net.Conn) *utls.UConn {
		u := utls.UClient(c, cfg, utls.HelloCustom)
		if err := u.ApplyPreset(&spec); err != nil {
			t.Fatalf("ApplyPreset: %v", err)
		}
		return u
	}
	ch, p1 := extOrderOf(t, pin)
	_, p2 := extOrderOf(t, pin)
	_, p3 := extOrderOf(t, pin)
	if p1 != p2 || p2 != p3 {
		t.Errorf("a reused pinned spec must yield an IDENTICAL extension order across connections; got %s / %s / %s", p1, p2, p3)
	}
	// The pinned hello still passes the existing TLS tells — only the static order distinguishes it.
	if !ch.HasGREASE() {
		t.Error("pinned Chrome hello should GREASE (else net.tls_grease_vs_ua already catches it; static order not isolated)")
	}
	if !ch.HasPostQuantumKeyShare() {
		t.Error("pinned Chrome_131 hello should advertise a PQ key share (else net.tls_pq_keyshare_vs_ua catches it)")
	}
	// The rule's JA4-engine GATE precondition: the edge must hint this hello's JA4 as a Chromium engine, or
	// the detector's _annotate_ext_order_static gate (ja4_browser_hint == "chrome") never opens. Grounds the
	// end-to-end positive: edge JA4 hint -> "chrome" -> gate opens -> static order convicts.
	if hint, ok := DefaultHints().Lookup(ch.JA4()); !ok || hint.Browser != "chrome" {
		t.Errorf("pinned Chrome_131 JA4 %q must hint browser=chrome for the rule's gate; got hint=%+v ok=%v",
			ch.JA4(), hint, ok)
	}
}
