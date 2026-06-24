// edge/fingerprint/grease — GREASE detection and filtering (RFC 8701).
// Drops reserved GREASE cipher/extension values so fingerprints stay stable across handshakes.

package fingerprint

import (
	"strconv"
	"strings"
)

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

// orderWithGREASE renders a uint16 list in WIRE ORDER as a hyphen-joined hex string, normalizing GREASE
// values to "g" — so the placement/order is captured while the random GREASE value stays stable across
// handshakes. JA4 *sorts* these lists (for stability across Chrome's per-connection extension permutation);
// this preserves the raw order, the stronger impostor tell (a pinned uTLS/curl-impersonate profile emits a
// fixed order; a non-Chrome stack emits an order Chrome's permuter never produces).
func orderWithGREASE(in []uint16) string {
	parts := make([]string, 0, len(in))
	for _, v := range in {
		if IsGREASE(v) {
			parts = append(parts, "g")
		} else {
			parts = append(parts, strconv.FormatUint(uint64(v), 16))
		}
	}
	return strings.Join(parts, "-")
}

// ExtOrder returns the TLS extension IDs in wire order (GREASE → "g") — the extension-order fingerprint.
func (c *ClientHello) ExtOrder() string { return orderWithGREASE(c.Extensions) }

// CipherOrder returns the cipher suites in wire order (GREASE → "g") — the cipher-order fingerprint.
func (c *ClientHello) CipherOrder() string { return orderWithGREASE(c.CipherSuites) }

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
