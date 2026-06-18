// edge/fingerprint/h2parse_test — assert ParsePreface reconstructs an H2Fingerprint from raw frames.
// Synthesises real-shaped client prefaces (Chrome/Firefox) with the http2 framer, then parses them back.

package fingerprint

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// buildPreface writes a client connection preface: magic + SETTINGS + (optional) WINDOW_UPDATE +
// PRIORITY frames + a HEADERS frame whose pseudo-headers appear in pseudoOrder (single-letter codes).
func buildPreface(t *testing.T, settings []http2.Setting, window uint32, priorities []http2.PriorityFrame, pseudoOrder []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&buf, nil)
	if err := fr.WriteSettings(settings...); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	if window != 0 {
		if err := fr.WriteWindowUpdate(0, window); err != nil {
			t.Fatalf("write window: %v", err)
		}
	}
	for _, p := range priorities {
		if err := fr.WritePriority(p.StreamID, p.PriorityParam); err != nil {
			t.Fatalf("write priority: %v", err)
		}
	}
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	vals := map[string]string{"m": "GET", "a": "edge", "s": "https", "p": "/"}
	names := map[string]string{"m": ":method", "a": ":authority", "s": ":scheme", "p": ":path"}
	for _, code := range pseudoOrder {
		_ = enc.WriteField(hpack.HeaderField{Name: names[code], Value: vals[code]})
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: hb.Bytes(), EndHeaders: true, EndStream: true,
	}); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	return buf.Bytes()
}

func TestParsePrefaceChrome(t *testing.T) {
	raw := buildPreface(t,
		[]http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingEnablePush, Val: 0},
			{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
			{ID: http2.SettingInitialWindowSize, Val: 6291456},
			{ID: http2.SettingMaxHeaderListSize, Val: 262144},
		},
		15663105, nil, []string{"m", "a", "s", "p"})

	fp, err := ParsePreface(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p"
	if got := fp.String(); got != want {
		t.Errorf("fingerprint\n got=%s\nwant=%s", got, want)
	}
	if fp.Browser() != "chrome" {
		t.Errorf("browser=%s want chrome", fp.Browser())
	}
}

func TestParsePrefaceFirefoxWithPriorities(t *testing.T) {
	raw := buildPreface(t,
		[]http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingInitialWindowSize, Val: 131072},
			{ID: http2.SettingMaxFrameSize, Val: 16384},
		},
		12517377,
		[]http2.PriorityFrame{
			{FrameHeader: http2.FrameHeader{StreamID: 3}, PriorityParam: http2.PriorityParam{Weight: 200}},
			{FrameHeader: http2.FrameHeader{StreamID: 5}, PriorityParam: http2.PriorityParam{Weight: 100}},
		},
		[]string{"m", "p", "a", "s"})

	fp, err := ParsePreface(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := "1:65536;4:131072;5:16384|12517377|3:0:0:200,5:0:0:100|m,p,a,s"
	if got := fp.String(); got != want {
		t.Errorf("fingerprint\n got=%s\nwant=%s", got, want)
	}
	if fp.Browser() != "firefox" {
		t.Errorf("browser=%s want firefox", fp.Browser())
	}
}

func TestParsePrefaceRejectsBadMagic(t *testing.T) {
	if _, err := ParsePreface(strings.NewReader("GET / HTTP/1.1\r\n\r\n......................")); err == nil {
		t.Fatal("want error on non-h2 preface")
	}
}

func TestParsePrefaceShortReadErrors(t *testing.T) {
	if _, err := ParsePreface(io.LimitReader(strings.NewReader(http2.ClientPreface), 5)); err == nil {
		t.Fatal("want error on truncated preface")
	}
}
