// edge/fingerprint/keyshare_test — post-quantum key-share detection cases.
// Real current Chrome offers X25519MLKEM768/Kyber768; a static impersonation template does not.

package fingerprint

import "testing"

func TestHasPostQuantumKeyShare(t *testing.T) {
	cases := []struct {
		name   string
		groups []uint16
		want   bool
	}{
		{"chrome 131+ MLKEM768", []uint16{0x11EC, 0x001d, 0x0017}, true},
		{"chrome 124-130 kyber draft", []uint16{0x6399, 0x001d}, true},
		{"static template, classical groups only", []uint16{0x001d, 0x0017, 0x0018}, false},
		{"empty supported_groups", nil, false},
	}
	for _, c := range cases {
		ch := &ClientHello{SupportedGroups: c.groups}
		if got := ch.HasPostQuantumKeyShare(); got != c.want {
			t.Errorf("%s: HasPostQuantumKeyShare=%v want %v", c.name, got, c.want)
		}
	}
}

// clientHelloWithGroups builds a well-formed ClientHello record advertising exactly the given
// supported_groups, so the PQ check is exercised over the real parser (parseExtensions), not a
// hand-set struct field.
func clientHelloWithGroups(groups ...uint16) []byte {
	exts := cat(
		extB(extServerName, []byte{0, 0, 0, 0, 0}),
		extB(extSupportedGroups, u16ListB(groups...)),
		extB(extSupportedVersions, []byte{0x06, 0x0a, 0x0a, 0x03, 0x04, 0x03, 0x03}),
	)
	chBody := cat(
		u16b(0x0303),
		make([]byte, 32),
		[]byte{0x00},
		u16ListB(0x1301, 0xc02b),
		[]byte{0x01, 0x00},
		append(u16b(uint16(len(exts))), exts...),
	)
	hs := cat([]byte{0x01, byte(len(chBody) >> 16), byte(len(chBody) >> 8), byte(len(chBody))}, chBody)
	return cat([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs)
}

// TestHasPostQuantumKeyShareFromWire validates the whole path: raw ClientHello bytes parsed by
// ParseClientHello, then the PQ group extracted from the real supported_groups extension.
func TestHasPostQuantumKeyShareFromWire(t *testing.T) {
	chPQ, err := ParseClientHello(clientHelloWithGroups(0x0a0a, 0x11EC, 0x001d, 0x0017))
	if err != nil {
		t.Fatal(err)
	}
	if !chPQ.HasPostQuantumKeyShare() {
		t.Error("wire ClientHello with X25519MLKEM768 (0x11EC) — HasPostQuantumKeyShare should be true")
	}

	chKyber, err := ParseClientHello(clientHelloWithGroups(0x6399, 0x001d))
	if err != nil {
		t.Fatal(err)
	}
	if !chKyber.HasPostQuantumKeyShare() {
		t.Error("wire ClientHello with Kyber768 draft (0x6399) — HasPostQuantumKeyShare should be true")
	}

	// buildClientHello advertises only classical groups (0x001d, 0x0017) — a static-template stack.
	chNoPQ, err := ParseClientHello(buildClientHello())
	if err != nil {
		t.Fatal(err)
	}
	if chNoPQ.HasPostQuantumKeyShare() {
		t.Error("classical-only ClientHello — HasPostQuantumKeyShare should be false")
	}
}
