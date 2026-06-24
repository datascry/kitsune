// edge/fingerprint/quic_tp — QUIC transport-parameters fingerprint from the inner ClientHello (ext 0x39).
// The QUIC-stack identity (quiche/cronet vs ngtcp2 vs quic-go) is in the TP id ORDER — independent of JA4.

package fingerprint

import (
	"strconv"
	"strings"
)

// isQUICGreaseTP reports whether a QUIC transport-parameter id is a reserved GREASE value (31*N+27, RFC 9000
// §18.1) — normalized away so the random GREASE id doesn't churn the fingerprint while its placement stays.
func isQUICGreaseTP(id uint64) bool { return id >= 27 && (id-27)%31 == 0 }

// QUICTransportParamOrder renders the QUIC transport parameters in wire ORDER as a hyphen-joined string of
// ids (hex, GREASE → "g"). The id SET+ORDER fingerprints the QUIC library/stack (QUIC Hunter, PAM 2024) and
// is NOT captured by JA4-over-QUIC, which only hashes the inner TLS ClientHello. Empty for non-QUIC hellos.
func (c *ClientHello) QUICTransportParamOrder() string {
	b := c.QUICTransportParams
	if len(b) == 0 {
		return ""
	}
	ids := make([]string, 0, 16)
	for i := 0; i < len(b); {
		id, n := readVarint(b[i:])
		if n == 0 {
			break
		}
		i += n
		plen, m := readVarint(b[i:])
		if m == 0 || i+m+int(plen) > len(b) {
			break // malformed length — stop rather than over-read
		}
		i += m + int(plen)
		if isQUICGreaseTP(id) {
			ids = append(ids, "g")
		} else {
			ids = append(ids, strconv.FormatUint(id, 16))
		}
	}
	return strings.Join(ids, "-")
}
