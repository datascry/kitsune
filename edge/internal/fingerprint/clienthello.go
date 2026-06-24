// edge/fingerprint/clienthello — parse a raw TLS ClientHello into its fingerprintable fields.
// Decodes record + handshake + extensions; the byte-level capture JA3/JA4 needs (cf. utls).

package fingerprint

import "errors"

// ErrMalformed is returned when the bytes are not a well-formed TLS ClientHello.
var ErrMalformed = errors.New("fingerprint: malformed ClientHello")

// Extension type constants we extract specially.
const (
	extServerName          uint16 = 0x0000
	extSupportedGroups     uint16 = 0x000a
	extECPointFormats      uint16 = 0x000b
	extSignatureAlgorithms uint16 = 0x000d
	extALPN                uint16 = 0x0010
	extSupportedVersions   uint16 = 0x002b
	extQUICTransportParams uint16 = 0x0039
)

// ClientHello holds the parsed fields used to compute JA3/JA4.
type ClientHello struct {
	Transport           string // "t" (TCP) or "q" (QUIC); defaults to "t"
	Version             uint16 // negotiated version (max from supported_versions, else legacy)
	LegacyVersion       uint16
	CipherSuites        []uint16
	Extensions          []uint16
	SupportedGroups     []uint16
	PointFormats        []uint8
	SignatureAlgorithms []uint16
	ALPN                []string
	HasSNI              bool
	QUICTransportParams []byte // raw quic_transport_parameters (ext 0x39) body; QUIC ClientHellos only
}

// reader is a bounds-checked big-endian byte cursor; once it overflows, err sticks.
type reader struct {
	b   []byte
	i   int
	err error
}

func (r *reader) need(n int) bool {
	if r.err != nil {
		return false
	}
	if n < 0 || r.i+n > len(r.b) {
		r.err = ErrMalformed
		return false
	}
	return true
}

func (r *reader) u8() uint8 {
	if !r.need(1) {
		return 0
	}
	v := r.b[r.i]
	r.i++
	return v
}

func (r *reader) u16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := uint16(r.b[r.i])<<8 | uint16(r.b[r.i+1])
	r.i += 2
	return v
}

func (r *reader) u24() int {
	if !r.need(3) {
		return 0
	}
	v := int(r.b[r.i])<<16 | int(r.b[r.i+1])<<8 | int(r.b[r.i+2])
	r.i += 3
	return v
}

func (r *reader) take(n int) []byte {
	if !r.need(n) {
		return nil
	}
	v := r.b[r.i : r.i+n]
	r.i += n
	return v
}

// u16list reads a length-prefixed (2-byte length) list of uint16s.
func (r *reader) u16list() []uint16 {
	n := int(r.u16())
	body := r.take(n)
	if r.err != nil || n%2 != 0 {
		if n%2 != 0 {
			r.err = ErrMalformed
		}
		return nil
	}
	out := make([]uint16, 0, n/2)
	for i := 0; i+1 < len(body); i += 2 {
		out = append(out, uint16(body[i])<<8|uint16(body[i+1]))
	}
	return out
}

// ParseClientHello parses a full TLS record containing a ClientHello (TCP transport).
func ParseClientHello(record []byte) (*ClientHello, error) {
	r := &reader{b: record}
	if r.u8() != 0x16 { // handshake record
		return nil, ErrMalformed
	}
	_ = r.u16() // record version
	recLen := int(r.u16())
	body := r.take(recLen)
	if r.err != nil {
		return nil, r.err
	}
	return ParseClientHelloHandshake(body, "t")
}

// ParseClientHelloHandshake parses a raw TLS handshake message (no record layer) — the form QUIC carries
// in its CRYPTO frames. transport is the JA4 transport marker ("t" for TCP, "q" for QUIC).
func ParseClientHelloHandshake(handshake []byte, transport string) (*ClientHello, error) {
	h := &reader{b: handshake}
	if h.u8() != 0x01 { // client_hello
		return nil, ErrMalformed
	}
	hsLen := h.u24()
	ch := &reader{b: h.take(hsLen)}
	if h.err != nil {
		return nil, h.err
	}

	out := &ClientHello{Transport: transport}
	out.LegacyVersion = ch.u16()
	out.Version = out.LegacyVersion
	_ = ch.take(32)           // random
	_ = ch.take(int(ch.u8())) // legacy session id
	out.CipherSuites = ch.u16list()
	_ = ch.take(int(ch.u8())) // compression methods

	// Extensions are optional.
	if ch.i < len(ch.b) {
		extTotal := int(ch.u16())
		ext := &reader{b: ch.take(extTotal)}
		parseExtensions(ext, out)
		if ext.err != nil {
			return nil, ext.err
		}
	}
	if ch.err != nil {
		return nil, ch.err
	}
	return out, nil
}

func parseExtensions(ext *reader, out *ClientHello) {
	for ext.i < len(ext.b) && ext.err == nil {
		etype := ext.u16()
		elen := int(ext.u16())
		data := ext.take(elen)
		if ext.err != nil {
			return
		}
		out.Extensions = append(out.Extensions, etype)
		parseExtensionBody(etype, data, out)
	}
}

func parseExtensionBody(etype uint16, data []byte, out *ClientHello) {
	d := &reader{b: data}
	switch etype {
	case extServerName:
		out.HasSNI = true
	case extSupportedGroups:
		out.SupportedGroups = d.u16list()
	case extSignatureAlgorithms:
		out.SignatureAlgorithms = d.u16list()
	case extECPointFormats:
		out.PointFormats = append([]uint8(nil), d.take(int(d.u8()))...)
	case extALPN:
		_ = d.u16() // ALPN protocol-list length
		for d.i < len(d.b) && d.err == nil {
			out.ALPN = append(out.ALPN, string(d.take(int(d.u8()))))
		}
	case extSupportedVersions:
		_ = d.u8() // versions-list length (1 byte)
		var best uint16
		for d.i < len(d.b) && d.err == nil {
			v := d.u16()
			if !IsGREASE(v) && v > best {
				best = v
			}
		}
		if best != 0 {
			out.Version = best
		}
	case extQUICTransportParams:
		out.QUICTransportParams = append([]byte(nil), data...)
	}
}
