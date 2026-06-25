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
// this preserves the raw order.
//
// NB (2026-06-25): a SINGLE-SHOT "order ∉ known Chrome set" rule is NOT viable — modern uTLS
// HelloChrome_Auto and curl-impersonate also SHUFFLE the order per connection (uTLS
// ShuffleChromeTLSExtensions), so there is no fixed legal-Chrome order to match and any single-hello check
// FPs on Chrome's own permutations. But that per-connection shuffle is exactly what makes the WITHIN-SESSION
// tell work: a real Chromium emits a DIFFERENT order on every connection, so a Chromium-JA4 session that
// repeats ONE order across >=2 connections is a pinned template — convicted by
// net.tls_ext_order_static_within_session (detector ingest._annotate_ext_order_static), grounded by the
// go-tls KS_STATICEXT evader and tls_ext_order_test.go. See docs/research-radar.md N2.
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
