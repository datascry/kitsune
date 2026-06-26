// edge/fingerprint/h2frames — count HTTP/2 frame types over a live connection to spot frame-level DoS.
// Covers the HTTP/2 DoS family: rapid reset (CVE-2023-44487), CONTINUATION flood (CVE-2024-27316), the
// 2019 control-frame floods (SETTINGS/PING — CVE-2019-9515/9512), and MadeYouReset (CVE-2025-8671): a
// client that COERCES the server to reset streams with malformed control frames instead of sending its
// own RST_STREAM, evading the rapid-reset signature.

package fingerprint

import "sync/atomic"

// H2 frame type codes (RFC 7540 §6 / RFC 9113).
const (
	frameHeaders      = 0x1
	framePriority     = 0x2
	frameRSTStream    = 0x3
	frameSettings     = 0x4
	frameWindowUpdate = 0x8
	framePing         = 0x6
	frameContinuation = 0x9
	frameHeaderLen    = 9 // length(3) + type(1) + flags(1) + R|streamID(4)
	priorityPayload   = 5 // RFC 9113 §6.3: a PRIORITY payload is exactly 5 bytes
	windowUpdateLen   = 4 // RFC 9113 §6.9: a WINDOW_UPDATE payload is exactly 4 bytes
)

// clientPrefaceLen is the byte length of the HTTP/2 client connection preface magic ("PRI * HTTP/2.0…").
const clientPrefaceLen = 24

// H2FrameScanner consumes the raw bytes of an HTTP/2 connection incrementally (across arbitrary Read
// boundaries) and counts the frame types the DoS-family signatures need. It is fed a *copy* of the
// connection bytes, so it only observes — it never alters what the HTTP/2 server reads. Counting is
// best-effort: a malformed stream simply yields whatever counts were parsed up to the malformation,
// never a panic.
type H2FrameScanner struct {
	prefaceSkipped int     // bytes of the 24-byte client preface magic still to consume
	hdr            [9]byte // partial frame header buffer
	hdrFilled      int     // bytes of hdr currently filled
	payloadLeft    int     // bytes of the current frame's payload still to skip
	// Payload-prefix capture state for the frames whose VALUE (not just type) we inspect — PRIORITY and
	// WINDOW_UPDATE. capLeft>0 means we are still buffering the inspected prefix of the current frame.
	capBuf    [priorityPayload]byte // inspected payload prefix (max 5 = PRIORITY)
	capFilled int                   // bytes of capBuf currently filled
	capLeft   int                   // inspected-prefix bytes still to capture
	capType   byte                  // frame type being inspected (0 = none)
	capStream uint32                // stream id of the inspected frame
	// Frame counters are atomic: Feed (the http2 server's single per-connection read goroutine) increments
	// them while the flood-detector methods (RapidReset/ContinuationFlood/ControlFrameFlood/MadeYouReset) are
	// read from concurrent per-stream handler goroutines. The parser state above is single-writer (only Feed)
	// so it needs no synchronisation; only these cross-goroutine counters do.
	Headers       atomic.Uint64
	RSTStreams    atomic.Uint64
	Continuations atomic.Uint64
	Settings      atomic.Uint64
	Pings         atomic.Uint64
	// MadeYouResets counts MALFORMED control frames that coerce a server-side stream reset (CVE-2025-8671):
	// a WINDOW_UPDATE with a zero increment, or a PRIORITY frame with the wrong length or a self-dependency.
	// No conformant client ever emits one — their mere repetition is the attack signature.
	MadeYouResets atomic.Uint64
}

// Feed advances the scanner over the next chunk of connection bytes.
func (s *H2FrameScanner) Feed(b []byte) {
	i := 0
	// Consume the client preface magic before any frames begin.
	if s.prefaceSkipped < clientPrefaceLen {
		skip := clientPrefaceLen - s.prefaceSkipped
		if skip > len(b)-i {
			skip = len(b) - i
		}
		s.prefaceSkipped += skip
		i += skip
	}
	for i < len(b) {
		if s.payloadLeft > 0 {
			// Capture the inspected payload prefix (PRIORITY / WINDOW_UPDATE) before skipping the rest.
			if s.capLeft > 0 {
				take := s.capLeft
				if take > len(b)-i {
					take = len(b) - i
				}
				copy(s.capBuf[s.capFilled:], b[i:i+take])
				s.capFilled += take
				s.capLeft -= take
				s.payloadLeft -= take
				i += take
				if s.capLeft == 0 {
					s.evalInspected()
				}
				continue
			}
			// Skipping the current frame's payload.
			skip := s.payloadLeft
			if skip > len(b)-i {
				skip = len(b) - i
			}
			s.payloadLeft -= skip
			i += skip
			continue
		}
		// Accumulate a 9-byte frame header (it may span Feed calls).
		need := frameHeaderLen - s.hdrFilled
		take := need
		if take > len(b)-i {
			take = len(b) - i
		}
		copy(s.hdr[s.hdrFilled:], b[i:i+take])
		s.hdrFilled += take
		i += take
		if s.hdrFilled < frameHeaderLen {
			return // header continues in a later chunk
		}
		// Full header: length is the first 3 bytes (big-endian), type the 4th, stream id the last 4
		// (high bit reserved).
		length := int(s.hdr[0])<<16 | int(s.hdr[1])<<8 | int(s.hdr[2])
		streamID := uint32(s.hdr[5]&0x7f)<<24 | uint32(s.hdr[6])<<16 | uint32(s.hdr[7])<<8 | uint32(s.hdr[8])
		switch s.hdr[3] {
		case frameHeaders:
			s.Headers.Add(1)
		case frameRSTStream:
			s.RSTStreams.Add(1)
		case frameContinuation:
			s.Continuations.Add(1)
		case frameSettings:
			s.Settings.Add(1)
		case framePing:
			s.Pings.Add(1)
		case framePriority:
			// A PRIORITY frame whose length is not exactly 5 is a FRAME_SIZE_ERROR the server resets on
			// (RFC 9113 §6.3) — a MadeYouReset coercion primitive, convictable without reading the payload.
			// A correctly-sized PRIORITY still needs its payload inspected for a self-dependency.
			if length != priorityPayload {
				s.MadeYouResets.Add(1)
			} else {
				s.beginCapture(framePriority, streamID, length, priorityPayload)
			}
		case frameWindowUpdate:
			// Inspect the 4-byte increment for a zero value (the FLOW_CONTROL/PROTOCOL_ERROR coercion).
			if length >= windowUpdateLen {
				s.beginCapture(frameWindowUpdate, streamID, length, windowUpdateLen)
			}
		}
		s.payloadLeft = length
		s.hdrFilled = 0
	}
}

// beginCapture arms payload-prefix buffering for an inspected frame (PRIORITY / WINDOW_UPDATE). `need` is
// the number of leading payload bytes to copy into capBuf; never more than the declared length.
func (s *H2FrameScanner) beginCapture(typ byte, streamID uint32, length, need int) {
	if need > length {
		need = length
	}
	s.capType = typ
	s.capStream = streamID
	s.capFilled = 0
	s.capLeft = need
}

// evalInspected scores the captured payload prefix against the MadeYouReset (CVE-2025-8671) primitives:
// a WINDOW_UPDATE with a zero increment, or a PRIORITY frame that makes a stream depend on itself. Both
// are spec violations that coerce a server-side RST_STREAM, and no conformant client emits either.
func (s *H2FrameScanner) evalInspected() {
	switch s.capType {
	case framePriority:
		// Stream dependency is the low 31 bits of the first 4 payload bytes (high bit = exclusive flag).
		dep := uint32(s.capBuf[0]&0x7f)<<24 | uint32(s.capBuf[1])<<16 | uint32(s.capBuf[2])<<8 | uint32(s.capBuf[3])
		if dep == s.capStream { // a stream cannot depend on itself (RFC 9113 §5.3.1)
			s.MadeYouResets.Add(1)
		}
	case frameWindowUpdate:
		inc := uint32(s.capBuf[0]&0x7f)<<24 | uint32(s.capBuf[1])<<16 | uint32(s.capBuf[2])<<8 | uint32(s.capBuf[3])
		if inc == 0 {
			s.MadeYouResets.Add(1)
		}
	}
	s.capType = 0
}

// RapidReset reports whether the connection's frame mix matches the CVE-2023-44487 signature: a large
// number of RST_STREAM frames that roughly tracks the HEADERS count (each opened stream is cancelled).
// A real browser cancels the occasional stream; it never resets at this scale. The threshold is
// deliberately conservative so a handful of legitimate cancellations never trips it.
func (s *H2FrameScanner) RapidReset() bool {
	const floor = 100
	rst := s.RSTStreams.Load()
	return rst >= floor && rst*2 >= s.Headers.Load()
}

// ContinuationFlood reports the CVE-2024-27316 signature: a flood of CONTINUATION frames (the attack
// follows a HEADERS frame with an endless CONTINUATION stream that never sets END_HEADERS, so the server
// buffers headers until it exhausts memory). A real client emits CONTINUATION only for an unusually large
// header block, and then just a handful — never at this scale.
func (s *H2FrameScanner) ContinuationFlood() bool {
	const floor = 50
	return s.Continuations.Load() >= floor
}

// ControlFrameFlood reports the 2019 control-frame floods (CVE-2019-9515 SETTINGS flood, CVE-2019-9512
// PING flood): a client spams SETTINGS or PING to force the server to expend work on ACKs. A real client
// sends its one preface SETTINGS and rarely a PING — never hundreds.
func (s *H2FrameScanner) ControlFrameFlood() bool {
	const floor = 100
	return s.Settings.Load()+s.Pings.Load() >= floor
}

// MadeYouReset reports the CVE-2025-8671 signature: a client that drives the server to reset streams with
// MALFORMED control frames (zero-increment WINDOW_UPDATE, mis-sized or self-dependent PRIORITY) instead of
// sending its own RST_STREAM — so the rapid-reset heuristic, which keys on client RST_STREAM frames, never
// fires. Each counted frame is a hard RFC 9113 violation a conformant browser never emits, so the floor is
// low: it only separates a deliberate coercion run from a lone stray frame, and stays unmistakably an
// attack signature (consistent with the other DoS-family floors, but justified by the malformation itself).
func (s *H2FrameScanner) MadeYouReset() bool {
	const floor = 10
	return s.MadeYouResets.Load() >= floor
}
