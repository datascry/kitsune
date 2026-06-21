// edge/fingerprint/h2frames — count HTTP/2 frame types over a live connection to spot frame-level DoS.
// Covers the HTTP/2 DoS family: rapid reset (CVE-2023-44487), CONTINUATION flood (CVE-2024-27316), and
// the 2019 control-frame floods (SETTINGS/PING — CVE-2019-9515/9512).

package fingerprint

import "sync/atomic"

// H2 frame type codes (RFC 7540 §6 / RFC 9113).
const (
	frameRSTStream    = 0x3
	frameSettings     = 0x4
	framePing         = 0x6
	frameHeaders      = 0x1
	frameContinuation = 0x9
	frameHeaderLen    = 9 // length(3) + type(1) + flags(1) + R|streamID(4)
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
	// Frame counters are atomic: Feed (the http2 server's single per-connection read goroutine) increments
	// them while the flood-detector methods (RapidReset/ContinuationFlood/ControlFrameFlood) are read from
	// concurrent per-stream handler goroutines. The parser state above is single-writer (only Feed) so it
	// needs no synchronisation; only these cross-goroutine counters do.
	Headers       atomic.Uint64
	RSTStreams    atomic.Uint64
	Continuations atomic.Uint64
	Settings      atomic.Uint64
	Pings         atomic.Uint64
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
		// Full header: length is the first 3 bytes (big-endian), type the 4th.
		length := int(s.hdr[0])<<16 | int(s.hdr[1])<<8 | int(s.hdr[2])
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
		}
		s.payloadLeft = length
		s.hdrFilled = 0
	}
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
