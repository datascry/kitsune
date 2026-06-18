// edge/fingerprint/h2frames — count HTTP/2 frame types over a live connection to spot rapid-reset DoS.
// CVE-2023-44487: a flood of HEADERS each immediately cancelled by RST_STREAM, bypassing stream limits.

package fingerprint

// H2 frame type codes (RFC 7540 §6). Only the two the rapid-reset signature needs are named.
const (
	frameHeaders   = 0x1
	frameRSTStream = 0x3
	frameHeaderLen = 9 // length(3) + type(1) + flags(1) + R|streamID(4)
)

// clientPrefaceLen is the byte length of the HTTP/2 client connection preface magic ("PRI * HTTP/2.0…").
const clientPrefaceLen = 24

// H2FrameScanner consumes the raw bytes of an HTTP/2 connection incrementally (across arbitrary Read
// boundaries) and counts HEADERS and RST_STREAM frames. It is fed a *copy* of the connection bytes, so
// it only observes — it never alters what the HTTP/2 server reads. Counting is best-effort: a malformed
// stream simply yields whatever counts were parsed up to the malformation, never a panic.
type H2FrameScanner struct {
	prefaceSkipped int    // bytes of the 24-byte client preface magic still to consume
	hdr            [9]byte // partial frame header buffer
	hdrFilled      int     // bytes of hdr currently filled
	payloadLeft    int     // bytes of the current frame's payload still to skip
	pendingType    byte    // type of the frame whose payload we are skipping
	Headers        uint64
	RSTStreams     uint64
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
			s.Headers++
		case frameRSTStream:
			s.RSTStreams++
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
	return s.RSTStreams >= floor && s.RSTStreams*2 >= s.Headers
}
