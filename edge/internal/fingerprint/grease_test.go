// edge/fingerprint/grease_test — GREASE detection + raw wire-order (ext/cipher) fingerprint rendering.
// Asserts GREASE normalization to "g" and that order is preserved (unlike JA4, which sorts).

package fingerprint

import "testing"

func TestExtAndCipherOrderPreserveWireOrderWithGREASE(t *testing.T) {
	// GREASE values (0x?a?a) become "g"; real values stay hex, in wire order (NOT sorted like JA4).
	ch := &ClientHello{
		Extensions:   []uint16{0x0a0a, 0x0000, 0x0017, 0xff01, 0x0010},
		CipherSuites: []uint16{0x1a1a, 0x1301, 0x1302, 0xc02b},
	}
	if got, want := ch.ExtOrder(), "g-0-17-ff01-10"; got != want {
		t.Errorf("ExtOrder=%q want %q", got, want)
	}
	if got, want := ch.CipherOrder(), "g-1301-1302-c02b"; got != want {
		t.Errorf("CipherOrder=%q want %q", got, want)
	}
}
