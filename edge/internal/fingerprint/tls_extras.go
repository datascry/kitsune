// edge/fingerprint/tls_extras — ClientHello micro-tells JA4 doesn't surface (N5).
// Key-share groups (actually-sent vs advertised), cert-compression, ECH/ALPS/padding — a per-stack tell set.

package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// TLSTicketID is a stable short id for the TLS-resumption ticket the client presented (the pre_shared_key
// identity or the TLS-1.2 session_ticket), or "" if none. It hashes the opaque ticket bytes so the value is
// fixed-width and carries no secret, while two clients presenting the SAME ticket collide on the same id — the
// coordination tell: a resumption ticket is client-specific session material, so one ticket arriving from
// distinct source IPs is one TLS identity shared across machines (a binding that survives JA4 rotation).
func (c *ClientHello) TLSTicketID() string {
	if len(c.PSKIdentity) == 0 {
		return ""
	}
	sum := sha256.Sum256(c.PSKIdentity)
	return hex.EncodeToString(sum[:8])
}

// tlsGroupNames maps the common named groups to short labels for display (others fall back to hex).
var tlsGroupNames = map[uint16]string{
	0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
	0x001d: "x25519", 0x001e: "x448",
	0x11ec: "mlkem768", 0x6399: "kyber768", // post-quantum hybrids
}

// certCompAlgNames maps RFC 8879 certificate-compression algorithm ids to names.
var certCompAlgNames = map[uint16]string{1: "zlib", 2: "brotli", 3: "zstd"}

func namedGroup(g uint16) string {
	if IsGREASE(g) {
		return "g"
	}
	if n, ok := tlsGroupNames[g]; ok {
		return n
	}
	return strconv.FormatUint(uint64(g), 16)
}

func (c *ClientHello) hasExt(id uint16) bool {
	for _, e := range c.Extensions {
		if e == id {
			return true
		}
	}
	return false
}

// KeyShareNames lists the groups that actually CARRY a key_share (ext 0x33), in order — distinct from
// supported_groups (advertised). A pinned/pre-PQ template advertises a PQ group but ships only an X25519
// share; real Chrome 131+ sends both X25519 and X25519MLKEM768 shares. Empty when no key_share was parsed.
func (c *ClientHello) KeyShareNames() string {
	parts := make([]string, 0, len(c.KeyShareGroups))
	for _, g := range c.KeyShareGroups {
		parts = append(parts, namedGroup(g))
	}
	return strings.Join(parts, "+")
}

// CertCompression lists the certificate_compression algorithms (ext 0x1b), in order.
func (c *ClientHello) CertCompression() string {
	parts := make([]string, 0, len(c.CertCompressAlgs))
	for _, a := range c.CertCompressAlgs {
		if n, ok := certCompAlgNames[a]; ok {
			parts = append(parts, n)
		} else {
			parts = append(parts, strconv.FormatUint(uint64(a), 16))
		}
	}
	return strings.Join(parts, "-")
}

// HasPQKeyShareSent reports whether a post-quantum hybrid group actually carries a key_share — the sharper
// check than HasPostQuantumKeyShare (which only sees supported_groups / advertised).
func (c *ClientHello) HasPQKeyShareSent() bool {
	for _, g := range c.KeyShareGroups {
		if g == groupX25519MLKEM768 || g == groupX25519Kyber768D0 {
			return true
		}
	}
	return false
}

// TLSExtras renders a compact, human-readable summary of the ClientHello micro-tells for the wire panel:
// ECH/ALPS/padding presence, certificate-compression algorithms, and the key_share groups actually sent.
func (c *ClientHello) TLSExtras() string {
	parts := make([]string, 0, 5)
	if c.hasExt(extECH) {
		parts = append(parts, "ECH")
	}
	if c.hasExt(extALPS) || c.hasExt(extALPSLegacy) {
		parts = append(parts, "ALPS")
	}
	if c.hasExt(extPadding) {
		parts = append(parts, "padding")
	}
	if cc := c.CertCompression(); cc != "" {
		parts = append(parts, "cert-comp:"+cc)
	}
	if ks := c.KeyShareNames(); ks != "" {
		parts = append(parts, "key-share:"+ks)
	}
	return strings.Join(parts, " · ")
}
