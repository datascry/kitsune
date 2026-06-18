// edge/fingerprint/grease — GREASE detection and filtering (RFC 8701).
// Drops reserved GREASE cipher/extension values so fingerprints stay stable across handshakes.

package fingerprint

// IsGREASE reports whether v is a GREASE value (0x0a0a, 0x1a1a, ..., 0xfafa).
func IsGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a }

// HasGREASE reports whether the ClientHello advertised any GREASE cipher or extension (RFC 8701). Every
// current browser (Chrome 55+, Firefox, Safari, Edge) injects GREASE; scripted TLS stacks (Python's
// OpenSSL, Go crypto/tls) do not — so a browser User-Agent over a GREASE-less handshake is a tell.
func (c *ClientHello) HasGREASE() bool {
	for _, v := range c.CipherSuites {
		if IsGREASE(v) {
			return true
		}
	}
	for _, v := range c.Extensions {
		if IsGREASE(v) {
			return true
		}
	}
	return false
}

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
