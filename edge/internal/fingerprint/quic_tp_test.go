// edge/fingerprint/quic_tp_test — QUIC transport-parameter order fingerprint + GREASE normalization.
// Asserts varint id/len walking yields the wire-order TP id list and that reserved (31N+27) ids become "g".

package fingerprint

import "testing"

func TestQUICTransportParamOrder(t *testing.T) {
	// TP body = sequence of varint(id) varint(len) value. ids: 1(len4), 4(len4), 27(GREASE,len0), 8(len1).
	body := []byte{
		0x01, 0x04, 0, 0, 0, 0, // id 1, len 4
		0x04, 0x04, 0, 0, 0, 0, // id 4, len 4
		0x1b, 0x00, // id 27 (31*0+27 = GREASE), len 0
		0x08, 0x01, 0, // id 8, len 1
	}
	ch := &ClientHello{QUICTransportParams: body}
	if got, want := ch.QUICTransportParamOrder(), "1-4-g-8"; got != want {
		t.Errorf("QUICTransportParamOrder=%q want %q", got, want)
	}
	// A non-QUIC ClientHello (no TP extension) yields the empty string.
	if got := (&ClientHello{}).QUICTransportParamOrder(); got != "" {
		t.Errorf("want empty for no transport params, got %q", got)
	}
}

func TestIsQUICGreaseTP(t *testing.T) {
	for _, g := range []uint64{27, 58, 89} {
		if !isQUICGreaseTP(g) {
			t.Errorf("%d should be GREASE", g)
		}
	}
	for _, ng := range []uint64{1, 4, 8, 26, 28} {
		if isQUICGreaseTP(ng) {
			t.Errorf("%d should NOT be GREASE", ng)
		}
	}
}
