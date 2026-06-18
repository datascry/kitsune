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
