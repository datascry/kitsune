// edge/fingerprint/h2frames_test — assert the frame counter and the rapid-reset (CVE-2023-44487) heuristic.
// Builds real HEADERS/RST_STREAM streams with the http2 framer, including split across chunk boundaries.

package fingerprint

import (
	"bytes"
	"testing"

	"golang.org/x/net/http2"
)

// buildFrameStream writes a client preface magic followed by nHeaders HEADERS frames and nRST
// RST_STREAM frames — the shape of a rapid-reset flood when both counts are high and roughly equal.
func buildFrameStream(t *testing.T, nHeaders, nRST int) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&buf, nil)
	for i := 0; i < nHeaders; i++ {
		if err := fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID: uint32(2*i + 1), BlockFragment: []byte{0x88}, EndHeaders: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < nRST; i++ {
		if err := fr.WriteRSTStream(uint32(2*i+1), http2.ErrCodeCancel); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestH2FrameScannerCounts(t *testing.T) {
	var s H2FrameScanner
	s.Feed(buildFrameStream(t, 120, 120))
	if s.Headers != 120 || s.RSTStreams != 120 {
		t.Fatalf("counts: headers=%d rst=%d, want 120/120", s.Headers, s.RSTStreams)
	}
	if !s.RapidReset() {
		t.Error("120 HEADERS + 120 RST_STREAM should match the rapid-reset signature")
	}
}

func TestH2FrameScannerChunkBoundaries(t *testing.T) {
	raw := buildFrameStream(t, 120, 120)
	// Feed in tiny, irregular chunks so frame headers and payloads straddle Feed calls.
	var s H2FrameScanner
	for i := 0; i < len(raw); i += 7 {
		end := i + 7
		if end > len(raw) {
			end = len(raw)
		}
		s.Feed(raw[i:end])
	}
	if s.Headers != 120 || s.RSTStreams != 120 {
		t.Fatalf("chunked counts: headers=%d rst=%d, want 120/120", s.Headers, s.RSTStreams)
	}
}

func TestH2FrameScannerLegitTrafficIsQuiet(t *testing.T) {
	// A normal session: a page's worth of requests and a single cancelled stream.
	var s H2FrameScanner
	s.Feed(buildFrameStream(t, 30, 1))
	if s.RapidReset() {
		t.Errorf("legit traffic (30 HEADERS, 1 RST) must not trip rapid-reset: rst=%d", s.RSTStreams)
	}
}

func TestH2FrameScannerManyHeadersFewResets(t *testing.T) {
	// A long-lived connection with lots of real requests but almost no resets is NOT rapid-reset.
	var s H2FrameScanner
	s.Feed(buildFrameStream(t, 500, 3))
	if s.RapidReset() {
		t.Errorf("500 HEADERS with 3 RST must not trip rapid-reset")
	}
}

func TestH2FrameScannerContinuationFlood(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&buf, nil)
	// One HEADERS that never ends, then a flood of CONTINUATION frames (CVE-2024-27316).
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x88}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 80; i++ {
		if err := fr.WriteContinuation(1, false, []byte{0x88}); err != nil {
			t.Fatal(err)
		}
	}
	var s H2FrameScanner
	s.Feed(buf.Bytes())
	if s.Continuations != 80 {
		t.Fatalf("continuations=%d, want 80", s.Continuations)
	}
	if !s.ContinuationFlood() {
		t.Error("80 CONTINUATION frames should match the flood signature")
	}
	if s.ControlFrameFlood() || s.RapidReset() {
		t.Error("a CONTINUATION flood must not be misclassified as a control-frame or rapid-reset flood")
	}
}

func TestH2FrameScannerControlFrameFlood(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&buf, nil)
	for i := 0; i < 60; i++ {
		if err := fr.WriteSettings(); err != nil {
			t.Fatal(err)
		}
		if err := fr.WritePing(false, [8]byte{}); err != nil {
			t.Fatal(err)
		}
	}
	var s H2FrameScanner
	s.Feed(buf.Bytes())
	if !s.ControlFrameFlood() {
		t.Errorf("60 SETTINGS + 60 PING should match the control-frame flood: settings=%d pings=%d", s.Settings, s.Pings)
	}
}

func TestH2FrameScannerLegitControlFramesQuiet(t *testing.T) {
	// A normal connection: the one preface SETTINGS and a keepalive PING — not a flood.
	var buf bytes.Buffer
	buf.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&buf, nil)
	_ = fr.WriteSettings()
	_ = fr.WritePing(false, [8]byte{})
	var s H2FrameScanner
	s.Feed(buf.Bytes())
	if s.ControlFrameFlood() || s.ContinuationFlood() {
		t.Error("a normal SETTINGS + PING must not trip any flood heuristic")
	}
}

func TestH2FrameScannerEmptyAndPartial(t *testing.T) {
	var s H2FrameScanner
	s.Feed(nil)
	s.Feed([]byte("PRI * HTTP/2")) // partial preface only
	if s.Headers != 0 || s.RSTStreams != 0 || s.RapidReset() {
		t.Error("partial preface alone must count nothing and not trip")
	}
}
