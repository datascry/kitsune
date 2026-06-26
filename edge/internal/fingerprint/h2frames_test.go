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
	if s.Headers.Load() != 120 || s.RSTStreams.Load() != 120 {
		t.Fatalf("counts: headers=%d rst=%d, want 120/120", s.Headers.Load(), s.RSTStreams.Load())
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
	if s.Headers.Load() != 120 || s.RSTStreams.Load() != 120 {
		t.Fatalf("chunked counts: headers=%d rst=%d, want 120/120", s.Headers.Load(), s.RSTStreams.Load())
	}
}

func TestH2FrameScannerLegitTrafficIsQuiet(t *testing.T) {
	// A normal session: a page's worth of requests and a single cancelled stream.
	var s H2FrameScanner
	s.Feed(buildFrameStream(t, 30, 1))
	if s.RapidReset() {
		t.Errorf("legit traffic (30 HEADERS, 1 RST) must not trip rapid-reset: rst=%d", s.RSTStreams.Load())
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
	if s.Continuations.Load() != 80 {
		t.Fatalf("continuations=%d, want 80", s.Continuations.Load())
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
		t.Errorf("60 SETTINGS + 60 PING should match the control-frame flood: settings=%d pings=%d", s.Settings.Load(), s.Pings.Load())
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
	if s.Headers.Load() != 0 || s.RSTStreams.Load() != 0 || s.RapidReset() {
		t.Error("partial preface alone must count nothing and not trip")
	}
}

// buildMadeYouResetStream writes a preface, one real HEADERS, then nWU zero-increment WINDOW_UPDATE frames
// and nPrio malformed PRIORITY frames (alternating wrong-length and self-dependent) — the MadeYouReset
// (CVE-2025-8671) coercion shape: the server is forced to reset streams, yet the client sends NO RST_STREAM.
func buildMadeYouResetStream(t *testing.T, nWU, nPrio int) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&buf, nil)
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x88}, EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < nWU; i++ {
		// A zero-increment WINDOW_UPDATE (RFC 9113 §6.9 PROTOCOL_ERROR) via a raw 4-byte zero payload —
		// the framer's WriteWindowUpdate rejects a zero increment, which is the whole point.
		if err := fr.WriteRawFrame(http2.FrameWindowUpdate, 0, uint32(2*i+3), []byte{0, 0, 0, 0}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < nPrio; i++ {
		sid := uint32(2*i + 101)
		if i%2 == 0 {
			// Wrong length: a PRIORITY payload that is not 5 bytes (FRAME_SIZE_ERROR).
			if err := fr.WriteRawFrame(http2.FramePriority, 0, sid, []byte{0, 0, 0, 0}); err != nil {
				t.Fatal(err)
			}
		} else {
			// Self-dependency: stream depends on itself (dep == own stream id), a 5-byte payload.
			payload := []byte{byte(sid >> 24), byte(sid >> 16), byte(sid >> 8), byte(sid), 0}
			if err := fr.WriteRawFrame(http2.FramePriority, 0, sid, payload); err != nil {
				t.Fatal(err)
			}
		}
	}
	return buf.Bytes()
}

func TestH2FrameScannerMadeYouReset(t *testing.T) {
	var s H2FrameScanner
	s.Feed(buildMadeYouResetStream(t, 12, 12))
	if got := s.MadeYouResets.Load(); got != 24 {
		t.Fatalf("madeyouresets=%d, want 24", got)
	}
	if !s.MadeYouReset() {
		t.Error("24 malformed coercion frames should match the MadeYouReset signature")
	}
	// The defining property: it coerces server resets WITHOUT client RST_STREAM, so rapid-reset stays quiet.
	if s.RapidReset() {
		t.Error("MadeYouReset sends zero RST_STREAM — it must NOT trip the rapid-reset heuristic")
	}
	if s.ContinuationFlood() || s.ControlFrameFlood() {
		t.Error("MadeYouReset must not be misclassified as another flood")
	}
}

func TestH2FrameScannerMadeYouResetChunkBoundaries(t *testing.T) {
	raw := buildMadeYouResetStream(t, 12, 12)
	var s H2FrameScanner
	for i := 0; i < len(raw); i += 3 { // tiny chunks so the inspected payload prefix straddles Feed calls
		end := i + 3
		if end > len(raw) {
			end = len(raw)
		}
		s.Feed(raw[i:end])
	}
	if got := s.MadeYouResets.Load(); got != 24 {
		t.Fatalf("chunked madeyouresets=%d, want 24", got)
	}
}

func TestH2FrameScannerLegitWindowUpdateAndPriorityQuiet(t *testing.T) {
	// A normal session: real WINDOW_UPDATE frames (non-zero increments) and a well-formed PRIORITY that
	// depends on another stream — exactly what a real browser emits. None is a coercion primitive.
	var buf bytes.Buffer
	buf.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&buf, nil)
	for i := 0; i < 50; i++ {
		if err := fr.WriteWindowUpdate(uint32(2*i+1), 65535); err != nil {
			t.Fatal(err)
		}
	}
	// A valid PRIORITY: stream 3 depends on stream 0 (the implicit root) — not self-dependent.
	if err := fr.WritePriority(3, http2.PriorityParam{StreamDep: 0, Weight: 15}); err != nil {
		t.Fatal(err)
	}
	var s H2FrameScanner
	s.Feed(buf.Bytes())
	if got := s.MadeYouResets.Load(); got != 0 {
		t.Fatalf("legit WINDOW_UPDATE/PRIORITY must count zero coercion frames, got %d", got)
	}
	if s.MadeYouReset() {
		t.Error("normal flow-control + priority traffic must not trip MadeYouReset")
	}
}

// TestH2FrameScannerConcurrentFeedAndReadIsRaceFree pins GAP-2: Feed (the http2 read goroutine) increments
// counters while the flood detectors are read from concurrent handler goroutines. With atomic counters this
// is race-free; `go test -race` would flag the old plain-uint64 fields.
func TestH2FrameScannerConcurrentFeedAndReadIsRaceFree(t *testing.T) {
	var s H2FrameScanner
	s.Feed(make([]byte, clientPrefaceLen)) // consume the preface
	frame := func(typ byte) []byte { return []byte{0, 0, 0, typ, 0, 0, 0, 0, 0} }
	done := make(chan struct{})
	go func() {
		for range 5000 {
			s.Feed(frame(frameRSTStream))
			s.Feed(frame(frameHeaders))
		}
		close(done)
	}()
	for {
		select {
		case <-done:
			if s.Headers.Load() != 5000 || s.RSTStreams.Load() != 5000 {
				t.Fatalf("counts after concurrent feed: headers=%d rst=%d", s.Headers.Load(), s.RSTStreams.Load())
			}
			return
		default:
			_ = s.RapidReset()
			_ = s.ContinuationFlood()
			_ = s.ControlFrameFlood()
			_ = s.MadeYouReset()
		}
	}
}
