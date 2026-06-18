// edge/fingerprint/keyshare — post-quantum key-share detection in the ClientHello supported_groups.
// Flags a current-Chrome handshake that omits X25519MLKEM768/Kyber768 (a lagging impersonation template).

package fingerprint

// Post-quantum hybrid key-exchange group codepoints offered by current browsers (IANA / draft):
//
//	X25519MLKEM768        0x11EC — Chrome 131+, Firefox 132+ (the standardised hybrid)
//	X25519Kyber768Draft00 0x6399 — Chrome 124-130 (the pre-standard draft)
const (
	groupX25519MLKEM768   uint16 = 0x11EC
	groupX25519Kyber768D0 uint16 = 0x6399
)

// HasPostQuantumKeyShare reports whether the ClientHello advertised a post-quantum hybrid group in its
// supported_groups. Every current Chrome/Firefox offers one by default; a TLS stack pinned to an older
// impersonation template does not, so its absence under a current-browser UA is a template-lag tell at
// the TLS layer — one the impersonation libraries must keep chasing as the browser rollout moves.
func (c *ClientHello) HasPostQuantumKeyShare() bool {
	for _, g := range c.SupportedGroups {
		if g == groupX25519MLKEM768 || g == groupX25519Kyber768D0 {
			return true
		}
	}
	return false
}
