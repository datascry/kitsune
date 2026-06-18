// edge/fingerprint/quic — decrypt a QUIC v1 Initial packet and extract its TLS ClientHello (RFC 9001).
// Derives the Initial keys from the DCID, removes header protection, AES-GCM-opens, reassembles CRYPTO.

package fingerprint

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// quicV1InitialSalt is the RFC 9001 §5.2 salt for QUIC version 1 Initial-key derivation.
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// ErrNotQUICInitial is returned when the bytes are not a QUIC v1 Initial long-header packet.
var ErrNotQUICInitial = errors.New("fingerprint: not a QUIC v1 Initial packet")

// hkdfExtract / hkdfExpandLabel implement the TLS 1.3 HKDF (RFC 8446 §7.1) QUIC uses for key schedule.
func hkdfExtract(salt, ikm []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := []byte{byte(length >> 8), byte(length), byte(len(full))}
	info = append(info, full...)
	info = append(info, 0x00) // empty context
	out := make([]byte, 0, length)
	var prev []byte
	for counter := byte(1); len(out) < length; counter++ {
		h := hmac.New(sha256.New, secret)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{counter})
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

// readVarint decodes a QUIC variable-length integer (RFC 9000 §16); returns value and bytes consumed.
func readVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	n := 1 << (b[0] >> 6) // 2-bit prefix selects 1/2/4/8 bytes
	if len(b) < n {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}

// cryptoFrag is one CRYPTO-frame fragment: handshake bytes at a stream offset.
type cryptoFrag struct {
	off  uint64
	data []byte
}

// ParseQUICInitial parses the ClientHello from a single QUIC v1 Initial packet (convenience wrapper).
func ParseQUICInitial(pkt []byte) (*ClientHello, error) {
	return ParseQUICInitials([][]byte{pkt})
}

// ParseQUICInitials decrypts one or more QUIC v1 client Initial packets (sharing a DCID) and reassembles
// their CRYPTO frames into the TLS ClientHello — a hello with post-quantum key shares exceeds one packet,
// so a passive QUIC fingerprinter must stitch the fragments, exactly as a QUIC endpoint does.
func ParseQUICInitials(pkts [][]byte) (*ClientHello, error) {
	var buf []byte
	for _, pkt := range pkts {
		frags, err := decryptInitialCrypto(pkt)
		if err != nil {
			continue // not a decryptable Initial (e.g. a padding-only retransmit) — skip
		}
		for _, f := range frags {
			need := int(f.off) + len(f.data)
			if need > len(buf) {
				buf = append(buf, make([]byte, need-len(buf))...)
			}
			copy(buf[f.off:], f.data)
		}
		if ch := tryParseHandshake(buf); ch != nil {
			return ch, nil
		}
	}
	return nil, ErrNotQUICInitial
}

// tryParseHandshake parses buf as a ClientHello only once it holds the complete handshake message.
func tryParseHandshake(buf []byte) *ClientHello {
	if len(buf) < 4 || buf[0] != 0x01 { // client_hello
		return nil
	}
	hsLen := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	if 4+hsLen > len(buf) {
		return nil // still fragmented — wait for more packets
	}
	ch, err := ParseClientHelloHandshake(buf, "q")
	if err != nil {
		return nil
	}
	return ch
}

// decryptInitialCrypto removes header + packet protection from one QUIC v1 Initial and returns its CRYPTO
// fragments. Keys come from the packet's own DCID (the Initial secrets are public).
func decryptInitialCrypto(pkt []byte) ([]cryptoFrag, error) {
	// Long header: 0b1???? form bit; QUIC v1 Initial has packet-type bits 00 (byte0 & 0x30 == 0).
	if len(pkt) < 7 || pkt[0]&0x80 == 0 {
		return nil, ErrNotQUICInitial
	}
	if binary.BigEndian.Uint32(pkt[1:5]) != 0x00000001 || pkt[0]&0x30 != 0x00 {
		return nil, ErrNotQUICInitial
	}
	i := 5
	dcidLen := int(pkt[i])
	i++
	if i+dcidLen > len(pkt) {
		return nil, ErrNotQUICInitial
	}
	dcid := pkt[i : i+dcidLen]
	i += dcidLen
	if i >= len(pkt) {
		return nil, ErrNotQUICInitial
	}
	scidLen := int(pkt[i])
	i++
	i += scidLen
	if i > len(pkt) {
		return nil, ErrNotQUICInitial
	}
	tokenLen, n := readVarint(pkt[i:])
	if n == 0 {
		return nil, ErrNotQUICInitial
	}
	i += n + int(tokenLen)
	if i < 0 || i > len(pkt) {
		return nil, ErrNotQUICInitial
	}
	length, n := readVarint(pkt[i:])
	if n == 0 {
		return nil, ErrNotQUICInitial
	}
	i += n
	pnOffset := i

	// Derive the client Initial AEAD/header-protection keys from the DCID (RFC 9001 §5.2).
	initialSecret := hkdfExtract(quicV1InitialSalt, dcid)
	clientSecret := hkdfExpandLabel(initialSecret, "client in", 32)
	key := hkdfExpandLabel(clientSecret, "quic key", 16)
	iv := hkdfExpandLabel(clientSecret, "quic iv", 12)
	hp := hkdfExpandLabel(clientSecret, "quic hp", 16)

	// Header protection (RFC 9001 §5.4): AES-ECB of a 16-byte sample taken 4 bytes past the PN offset.
	if pnOffset+4+16 > len(pkt) {
		return nil, ErrNotQUICInitial
	}
	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, pkt[pnOffset+4:pnOffset+4+16])

	hdr := make([]byte, pnOffset) // reconstruct the unprotected header for the AEAD AAD
	copy(hdr, pkt[:pnOffset])
	hdr[0] = pkt[0] ^ (mask[0] & 0x0f)
	pnLen := int(hdr[0]&0x03) + 1
	pn := make([]byte, pnLen)
	for j := 0; j < pnLen; j++ {
		pn[j] = pkt[pnOffset+j] ^ mask[1+j]
	}
	hdr = append(hdr, pn...)

	// AEAD nonce = iv XOR left-padded packet number; AAD = the unprotected header.
	end := pnOffset + int(length)
	if end > len(pkt) || pnOffset+pnLen > end {
		return nil, ErrNotQUICInitial
	}
	ciphertext := pkt[pnOffset+pnLen : end]
	nonce := make([]byte, 12)
	copy(nonce, iv)
	for j := 0; j < pnLen; j++ {
		nonce[12-pnLen+j] ^= pn[j]
	}
	aead, err := cipher.NewGCM(block2(key))
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, hdr)
	if err != nil {
		return nil, err
	}
	return cryptoFrames(plaintext)
}

func block2(key []byte) cipher.Block {
	b, _ := aes.NewCipher(key) // key length already validated (16 bytes)
	return b
}

// cryptoFrames walks a decrypted Initial payload and returns its CRYPTO-frame fragments (RFC 9000 §19.6),
// skipping PADDING/PING/ACK. Each fragment is handshake bytes at a stream offset, stitched by the caller.
func cryptoFrames(payload []byte) ([]cryptoFrag, error) {
	var out []cryptoFrag
	i := 0
	for i < len(payload) {
		ft := payload[i]
		i++
		switch ft {
		case 0x00, 0x01: // PADDING, PING
			continue
		case 0x02, 0x03: // ACK (with/without ECN) — stop; the rest is not client CRYPTO
			return out, nil
		case 0x06: // CRYPTO: offset, length, data
			off, n := readVarint(payload[i:])
			if n == 0 {
				return nil, ErrNotQUICInitial
			}
			i += n
			ln, n := readVarint(payload[i:])
			if n == 0 {
				return nil, ErrNotQUICInitial
			}
			i += n
			if i+int(ln) > len(payload) {
				return nil, ErrNotQUICInitial
			}
			out = append(out, cryptoFrag{off: off, data: append([]byte(nil), payload[i:i+int(ln)]...)})
			i += int(ln)
		default:
			return out, nil // an unexpected frame; return the CRYPTO collected so far
		}
	}
	return out, nil
}
