// edge/fingerprint/tls_extras_test — ClientHello micro-tell extraction (key-share, cert-comp, ECH/ALPS).
// Asserts the summary names groups/algos, marks PQ key_share actually-sent, and reflects ECH/ALPS presence.

package fingerprint

import "testing"

func TestTLSExtrasSummary(t *testing.T) {
	ch := &ClientHello{
		Extensions:       []uint16{extECH, extALPS, extPadding, extKeyShare, extCertCompression},
		KeyShareGroups:   []uint16{0x001d, 0x11ec}, // x25519 + mlkem768 (real Chrome 131+ sends both)
		CertCompressAlgs: []uint16{2},              // brotli
	}
	got := ch.TLSExtras()
	want := "ECH · ALPS · padding · cert-comp:brotli · key-share:x25519+mlkem768" // gitleaks:allow group names, not a credential
	if got != want {
		t.Errorf("TLSExtras=%q want %q", got, want)
	}
	if !ch.HasPQKeyShareSent() {
		t.Error("a sent MLKEM768 key_share must register as PQ-sent")
	}
	// Advertised-but-not-sent: PQ only in supported_groups, key_share carries x25519 only.
	stale := &ClientHello{KeyShareGroups: []uint16{0x001d}, SupportedGroups: []uint16{0x001d, 0x11ec}}
	if stale.HasPQKeyShareSent() {
		t.Error("a key_share without a PQ group must NOT register as PQ-sent (the stale-template tell)")
	}
	if !stale.HasPostQuantumKeyShare() {
		t.Error("PQ is still advertised in supported_groups")
	}
}
