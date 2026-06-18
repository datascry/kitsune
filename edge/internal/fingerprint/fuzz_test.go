// edge/fingerprint/fuzz_test — fuzz the adversarial-input parsers (untrusted ClientHello + h2 preface).
// The edge parses these straight off arbitrary client sockets; neither may panic on malformed bytes.

package fingerprint

import (
	"bytes"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// validPreface builds a well-formed Chrome-shaped client preface as a fuzz seed, so coverage-guided
// fuzzing starts from the frame-parsing paths rather than only the magic-check rejection.
func validPreface() []byte {
	var buf bytes.Buffer
	buf.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&buf, nil)
	_ = fr.WriteSettings(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6291456},
	)
	_ = fr.WriteWindowUpdate(0, 15663105)
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
	_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hb.Bytes(), EndHeaders: true})
	return buf.Bytes()
}

func FuzzParsePreface(f *testing.F) {
	f.Add(validPreface())
	f.Add([]byte(http2.ClientPreface))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		// Contract: never panic on arbitrary bytes. An error return is the expected outcome for junk.
		_, _ = ParsePreface(bytes.NewReader(data))
	})
}

func FuzzH2FrameScanner(f *testing.F) {
	f.Add(validPreface())
	f.Add([]byte(http2.ClientPreface))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		// The scanner is fed copies of raw connection bytes; arbitrary input must never panic.
		var s H2FrameScanner
		s.Feed(data)
		_ = s.RapidReset()
	})
}

func FuzzParseClientHello(f *testing.F) {
	f.Add(buildClientHello())
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseClientHello(data)
	})
}
