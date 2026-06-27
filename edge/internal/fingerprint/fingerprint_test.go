// edge/fingerprint/fingerprint_test — table-driven tests for the fingerprint engine.
// Builds a synthetic ClientHello and asserts the parser, JA3, JA4, GREASE, and hints.

package fingerprint

import (
	"crypto/md5"
	"encoding/hex"
	"reflect"
	"regexp"
	"testing"
)

// -- byte builders -----------------------------------------------------

func u16b(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func u16ListB(vs ...uint16) []byte {
	var body []byte
	for _, v := range vs {
		body = append(body, u16b(v)...)
	}
	return append(u16b(uint16(len(body))), body...)
}

func extB(etype uint16, body []byte) []byte {
	out := append(u16b(etype), u16b(uint16(len(body)))...)
	return append(out, body...)
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// buildClientHello assembles a complete, well-formed ClientHello TLS record.
func buildClientHello() []byte {
	exts := cat(
		extB(extServerName, []byte{0, 0, 0, 0, 0}),
		extB(extSupportedGroups, u16ListB(0x0a0a, 0x001d, 0x0017)),
		extB(extECPointFormats, []byte{0x01, 0x00}),
		extB(extSignatureAlgorithms, u16ListB(0x0403, 0x0804)),
		extB(extALPN, append(u16b(3), 0x02, 'h', '2')),
		extB(extSupportedVersions, []byte{0x06, 0x0a, 0x0a, 0x03, 0x04, 0x03, 0x03}),
	)
	chBody := cat(
		u16b(0x0303),                     // legacy_version
		make([]byte, 32),                 // random
		[]byte{0x00},                     // session id length 0
		u16ListB(0x0a0a, 0x1301, 0xc02b), // cipher suites (GREASE + 2 real)
		[]byte{0x01, 0x00},               // compression methods
		append(u16b(uint16(len(exts))), exts...),
	)
	hs := cat([]byte{0x01, byte(len(chBody) >> 16), byte(len(chBody) >> 8), byte(len(chBody))}, chBody)
	return cat([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs)
}

// -- parser ------------------------------------------------------------

func TestHasGREASE(t *testing.T) {
	c, err := ParseClientHello(buildClientHello())
	if err != nil {
		t.Fatal(err)
	}
	if !c.HasGREASE() {
		t.Error("buildClientHello advertises a GREASE cipher (0x0a0a) — HasGREASE should be true")
	}
	if (&ClientHello{CipherSuites: []uint16{0x1301, 0xc02b}}).HasGREASE() {
		t.Error("no GREASE values present — HasGREASE should be false")
	}
	if !(&ClientHello{Extensions: []uint16{0x1a1a}}).HasGREASE() {
		t.Error("0x1a1a is a GREASE extension — HasGREASE should be true")
	}
}

func TestParseClientHello(t *testing.T) {
	c, err := ParseClientHello(buildClientHello())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.Version != 0x0304 || c.LegacyVersion != 0x0303 {
		t.Errorf("version=%#x legacy=%#x", c.Version, c.LegacyVersion)
	}
	if !reflect.DeepEqual(c.CipherSuites, []uint16{0x0a0a, 0x1301, 0xc02b}) {
		t.Errorf("ciphers=%v", c.CipherSuites)
	}
	if !reflect.DeepEqual(c.Extensions, []uint16{0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x002b}) {
		t.Errorf("exts=%v", c.Extensions)
	}
	if !reflect.DeepEqual(c.SupportedGroups, []uint16{0x0a0a, 0x001d, 0x0017}) {
		t.Errorf("groups=%v", c.SupportedGroups)
	}
	if !reflect.DeepEqual(c.PointFormats, []uint8{0x00}) {
		t.Errorf("formats=%v", c.PointFormats)
	}
	if !reflect.DeepEqual(c.SignatureAlgorithms, []uint16{0x0403, 0x0804}) {
		t.Errorf("sigs=%v", c.SignatureAlgorithms)
	}
	if !reflect.DeepEqual(c.ALPN, []string{"h2"}) {
		t.Errorf("alpn=%v", c.ALPN)
	}
	if !c.HasSNI {
		t.Error("expected SNI")
	}
}

// helloWithExts assembles a ClientHello whose extension block is exactly `exts`.
func helloWithExts(exts []byte) []byte {
	chBody := cat(
		u16b(0x0303), make([]byte, 32), []byte{0x00},
		u16ListB(0x1301), []byte{0x01, 0x00},
		append(u16b(uint16(len(exts))), exts...),
	)
	hs := cat([]byte{0x01, byte(len(chBody) >> 16), byte(len(chBody) >> 8), byte(len(chBody))}, chBody)
	return cat([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs)
}

// pskExt builds a pre_shared_key (0x29) body: identities<> (one identity + ticket-age) + dummy binders<>.
func pskExt(identity []byte) []byte {
	ident := cat(u16b(uint16(len(identity))), identity, u32b(0)) // identity + obfuscated_ticket_age
	idents := append(u16b(uint16(len(ident))), ident...)
	binders := append(u16b(3), 0x20, 0x00, 0x00) // a (bogus) binder list; we never parse it
	return extB(extPreSharedKey, cat(idents, binders))
}

func u32b(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func TestTLSTicketID(t *testing.T) {
	t.Run("pre_shared_key", func(t *testing.T) {
		c, err := ParseClientHello(helloWithExts(pskExt([]byte("ticket-A"))))
		if err != nil {
			t.Fatal(err)
		}
		if string(c.PSKIdentity) != "ticket-A" || c.TLSTicketID() == "" {
			t.Errorf("psk identity=%q id=%q", c.PSKIdentity, c.TLSTicketID())
		}
	})
	t.Run("session_ticket non-empty", func(t *testing.T) {
		c, _ := ParseClientHello(helloWithExts(extB(extSessionTicket, []byte("tls12-ticket"))))
		if c.TLSTicketID() == "" {
			t.Error("a presented TLS-1.2 session ticket should yield an id")
		}
	})
	t.Run("session_ticket empty is a request, not a ticket", func(t *testing.T) {
		c, _ := ParseClientHello(helloWithExts(extB(extSessionTicket, nil)))
		if c.TLSTicketID() != "" {
			t.Errorf("empty session_ticket (resumption REQUEST) must not be an id, got %q", c.TLSTicketID())
		}
	})
	t.Run("none", func(t *testing.T) {
		c, _ := ParseClientHello(buildClientHello())
		if c.TLSTicketID() != "" {
			t.Errorf("no ticket extension should yield empty id, got %q", c.TLSTicketID())
		}
	})
	t.Run("same ticket collides, different tickets differ", func(t *testing.T) {
		a, _ := ParseClientHello(helloWithExts(pskExt([]byte("shared-ticket"))))
		b, _ := ParseClientHello(helloWithExts(pskExt([]byte("shared-ticket"))))
		c, _ := ParseClientHello(helloWithExts(pskExt([]byte("other-ticket"))))
		if a.TLSTicketID() != b.TLSTicketID() {
			t.Error("the same ticket must yield the same id (the coordination collision)")
		}
		if a.TLSTicketID() == c.TLSTicketID() {
			t.Error("distinct tickets must yield distinct ids")
		}
	})
}

func TestParseRejectsMalformed(t *testing.T) {
	good := buildClientHello()
	cases := map[string][]byte{
		"empty":          {},
		"bad-record":     {0x17, 0x03, 0x01, 0x00, 0x00},
		"truncated-body": good[:10],
		"bad-handshake":  {0x16, 0x03, 0x01, 0x00, 0x01, 0x02},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseClientHello(in); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestParseNoExtensions(t *testing.T) {
	chBody := cat(u16b(0x0303), make([]byte, 32), []byte{0x00}, u16ListB(0x1301), []byte{0x01, 0x00})
	hs := cat([]byte{0x01, 0x00, byte(len(chBody) >> 8), byte(len(chBody))}, chBody)
	record := cat([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs)
	c, err := ParseClientHello(record)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.Version != 0x0303 || len(c.Extensions) != 0 {
		t.Errorf("version=%#x exts=%v", c.Version, c.Extensions)
	}
}

func TestParseOddCipherList(t *testing.T) {
	chBody := cat(
		u16b(0x0303), make([]byte, 32), []byte{0x00},
		[]byte{0x00, 0x03, 0x13, 0x01, 0x00}, // cipher list length 3 (odd) -> malformed
		[]byte{0x01, 0x00},
	)
	hs := cat([]byte{0x01, 0x00, byte(len(chBody) >> 8), byte(len(chBody))}, chBody)
	record := cat([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs)
	if _, err := ParseClientHello(record); err == nil {
		t.Error("expected error on odd-length cipher list")
	}
}

func TestParseTruncatedExtension(t *testing.T) {
	// extension declares length 8 but only provides 2 bytes.
	exts := append(u16b(extECPointFormats), u16b(8)...)
	exts = append(exts, 0x01, 0x00)
	chBody := cat(
		u16b(0x0303), make([]byte, 32), []byte{0x00},
		u16ListB(0x1301), []byte{0x01, 0x00},
		append(u16b(uint16(len(exts))), exts...),
	)
	hs := cat([]byte{0x01, 0x00, byte(len(chBody) >> 8), byte(len(chBody))}, chBody)
	record := cat([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs)
	if _, err := ParseClientHello(record); err == nil {
		t.Error("expected error on truncated extension")
	}
}

func TestSupportedVersionsAllGREASE(t *testing.T) {
	exts := extB(extSupportedVersions, []byte{0x02, 0x0a, 0x0a}) // only a GREASE version
	chBody := cat(
		u16b(0x0303), make([]byte, 32), []byte{0x00},
		u16ListB(0x1301), []byte{0x01, 0x00},
		append(u16b(uint16(len(exts))), exts...),
	)
	hs := cat([]byte{0x01, 0x00, byte(len(chBody) >> 8), byte(len(chBody))}, chBody)
	record := cat([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs)
	c, err := ParseClientHello(record)
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != 0x0303 { // falls back to legacy when no real version offered
		t.Errorf("version=%#x", c.Version)
	}
}

// -- JA3 ---------------------------------------------------------------

func TestJA3(t *testing.T) {
	c, _ := ParseClientHello(buildClientHello())
	want := "772,4865-49195,0-10-11-13-16-43,29-23,0"
	if got := c.JA3String(); got != want {
		t.Errorf("ja3 string = %q want %q", got, want)
	}
	sum := md5.Sum([]byte(want))
	if got := c.JA3(); got != hex.EncodeToString(sum[:]) {
		t.Errorf("ja3 hash mismatch: %s", got)
	}
}

// -- JA4 ---------------------------------------------------------------

func TestJA4(t *testing.T) {
	c, _ := ParseClientHello(buildClientHello())
	ja4 := c.JA4()
	re := regexp.MustCompile(`^t13d0206h2_[0-9a-f]{12}_[0-9a-f]{12}$`)
	if !re.MatchString(ja4) {
		t.Errorf("ja4 = %q does not match expected shape", ja4)
	}
}

func TestJA4ChangesWithCiphers(t *testing.T) {
	a := &ClientHello{Transport: "t", Version: 0x0304, CipherSuites: []uint16{0x1301}}
	b := &ClientHello{Transport: "t", Version: 0x0304, CipherSuites: []uint16{0x1302}}
	if a.JA4() == b.JA4() {
		t.Error("expected different JA4 for different ciphers")
	}
}

func TestJA4Helpers(t *testing.T) {
	if ja4Version(0x0301) != "10" || ja4Version(0xffff) != "00" {
		t.Error("ja4Version")
	}
	if ja4ALPN(nil) != "00" || ja4ALPN([]string{""}) != "00" || ja4ALPN([]string{"x"}) != "xx" {
		t.Error("ja4ALPN")
	}
	if twoDigit(5) != "05" || twoDigit(150) != "99" {
		t.Error("twoDigit")
	}
}

// -- GREASE + hints ----------------------------------------------------

func TestGREASE(t *testing.T) {
	if !IsGREASE(0x0a0a) || !IsGREASE(0xfafa) || IsGREASE(0x1301) {
		t.Error("IsGREASE")
	}
	if got := filterGREASE([]uint16{0x0a0a, 0x1301}); !reflect.DeepEqual(got, []uint16{0x1301}) {
		t.Errorf("filterGREASE=%v", got)
	}
}

func TestHints(t *testing.T) {
	table := HintTable{"t13d0206h2_aaaaaaaaaaaa_bbbbbbbbbbbb": {Browser: "chrome", OS: "windows"}}
	if h, ok := table.Lookup("t13d0206h2_aaaaaaaaaaaa_bbbbbbbbbbbb"); !ok || h.Browser != "chrome" {
		t.Errorf("hint lookup: %+v ok=%v", h, ok)
	}
	if h, ok := table.Lookup("nope"); ok || h != Unknown {
		t.Errorf("expected Unknown, got %+v ok=%v", h, ok)
	}
}
