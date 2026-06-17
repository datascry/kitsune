// edge/fingerprint/grease — GREASE detection and filtering (RFC 8701).
// Drops reserved GREASE cipher/extension values so fingerprints stay stable across handshakes.

package fingerprint

// IsGREASE reports whether v is a GREASE value (0x0a0a, 0x1a1a, ..., 0xfafa).
func IsGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a }

// filterGREASE returns a copy of in with GREASE values removed.
func filterGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !IsGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}
