// edge/fingerprint/slowhttp — detect HTTP/1.1 slow-header (slowloris) connections.
// Times how a request's header block arrives; flags one that dribbles in incomplete past a time/byte budget.

package fingerprint

import "time"

// SlowLorisScanner observes the raw bytes of an HTTP/1.1 connection incrementally (a *copy*, like
// H2FrameScanner — it only watches, never alters what the server reads) and times how the request line +
// headers arrive. A slowloris holds the connection open by dribbling a few header bytes every several
// seconds and never sending the terminating CRLFCRLF, so the server's request read never completes — the
// connection table is exhausted with cheap, near-idle sockets. A real client sends its whole request header
// in one burst within milliseconds, so an *incomplete* header past a multi-second budget with only a trickle
// of bytes is the attack signature — distinct from mere network latency, which delays the whole burst, not
// its completion. The H2 analogues (endless CONTINUATION / slow headers over HTTP/2) are already covered by
// H2FrameScanner.ContinuationFlood; this is the HTTP/1.1 partial-header hold the frame scanner cannot see.
//
// Single-writer: only the per-connection read goroutine calls Feed. The detector reads are cheap value
// reads of the same goroutine's state (or a post-close snapshot), so no synchronisation is needed.
type SlowLorisScanner struct {
	started     bool
	headerDone  bool      // saw the CRLFCRLF that terminates the request header block
	firstByteAt time.Time // when the first request byte arrived
	totalBytes  int       // request bytes seen so far (header phase)
	crlf        int       // rolling match state for "\r\n\r\n" (0..4), across arbitrary read boundaries
}

// Feed advances the scanner over the next chunk of connection bytes, observed at time now. Once the header
// block has completed it is a no-op (the slow-header window is over; request bodies are out of scope here).
func (s *SlowLorisScanner) Feed(b []byte, now time.Time) {
	if s.headerDone || len(b) == 0 {
		return
	}
	if !s.started {
		s.started = true
		s.firstByteAt = now
	}
	s.totalBytes += len(b)
	const pat = "\r\n\r\n"
	for _, c := range b {
		if c == pat[s.crlf] {
			s.crlf++
			if s.crlf == len(pat) {
				s.headerDone = true
				return
			}
		} else if c == '\r' {
			s.crlf = 1 // the only viable restart prefix of the pattern is a fresh '\r'
		} else {
			s.crlf = 0
		}
	}
}

// HeaderComplete reports whether a full request header block (CRLFCRLF) has been observed. Its negative is
// the liveness half of the slowloris signature: the request never finished arriving.
func (s *SlowLorisScanner) HeaderComplete() bool { return s.headerDone }

// SlowRequest reports the slowloris signature as of time now: the request header block has NOT completed,
// the connection has been open at least minAge, and fewer than maxBytes have arrived — a connection held
// open by a trickle of partial-header bytes. The caller supplies the budget (e.g. 10s / 8 KiB); a real
// browser completes its header burst in milliseconds and well under any sane byte budget, so this never
// fires on a legitimately slow (high-latency) but complete request.
func (s *SlowLorisScanner) SlowRequest(now time.Time, minAge time.Duration, maxBytes int) bool {
	return s.started && !s.headerDone && s.totalBytes < maxBytes && now.Sub(s.firstByteAt) >= minAge
}
