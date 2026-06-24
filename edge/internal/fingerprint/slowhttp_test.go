// edge/fingerprint/slowhttp_test — cases for the HTTP/1.1 slow-header (slowloris) scanner.
// Deterministic: timestamps are injected, so the time-based signature is tested without real waiting.

package fingerprint

import (
	"testing"
	"time"
)

func TestSlowLorisDetectsDribbledIncompleteHeaders(t *testing.T) {
	s := &SlowLorisScanner{}
	base := time.Unix(1000, 0)
	// Partial headers dribble in over 12s and never send the terminating CRLFCRLF (the slowloris hold).
	s.Feed([]byte("GET / HTTP/1.1\r\n"), base)
	s.Feed([]byte("Host: example\r\n"), base.Add(4*time.Second))
	s.Feed([]byte("X-Pad: aaaa\r\n"), base.Add(12*time.Second))
	if s.HeaderComplete() {
		t.Fatal("header must still be incomplete (no CRLFCRLF sent)")
	}
	if !s.SlowRequest(base.Add(12*time.Second), 10*time.Second, 8192) {
		t.Error("expected the slowloris signature: incomplete header held past the age budget")
	}
}

func TestSlowLorisIgnoresCompleteHeaderBurst(t *testing.T) {
	s := &SlowLorisScanner{}
	base := time.Unix(1000, 0)
	// A real client sends its whole request header in one burst.
	s.Feed([]byte("GET / HTTP/1.1\r\nHost: example\r\nAccept: */*\r\n\r\n"), base)
	if !s.HeaderComplete() {
		t.Fatal("a full header burst must register as complete")
	}
	// Even checked far in the future, a completed request must never flag as slowloris.
	if s.SlowRequest(base.Add(60*time.Second), 10*time.Second, 8192) {
		t.Error("a completed request must never flag as a slow-HTTP attack")
	}
}

func TestSlowLorisNotYetPastAgeBudget(t *testing.T) {
	s := &SlowLorisScanner{}
	base := time.Unix(1000, 0)
	s.Feed([]byte("GET / HTTP/1.1\r\n"), base)
	// Incomplete, but only 3s old — under the 10s budget, so not yet the attack signature.
	if s.SlowRequest(base.Add(3*time.Second), 10*time.Second, 8192) {
		t.Error("must not flag before the age budget elapses")
	}
}

func TestSlowLorisIncompleteButBulkyIsNotFlagged(t *testing.T) {
	s := &SlowLorisScanner{}
	base := time.Unix(1000, 0)
	// A large incomplete header (>= maxBytes) is a different shape (oversized header), not the cheap
	// near-idle slowloris hold — the byte budget excludes it.
	s.Feed(make([]byte, 9000), base) // 9000 bytes, no CRLFCRLF, but over the 8 KiB budget
	if s.SlowRequest(base.Add(20*time.Second), 10*time.Second, 8192) {
		t.Error("a bulky incomplete header is not the slowloris (trickle) signature")
	}
}

func TestSlowLorisTracksCRLFAcrossReadBoundaries(t *testing.T) {
	s := &SlowLorisScanner{}
	base := time.Unix(1000, 0)
	// The terminating CRLFCRLF is split across two reads — the rolling matcher must still catch it.
	s.Feed([]byte("GET / HTTP/1.1\r\nHost: x\r"), base)
	s.Feed([]byte("\n\r\n"), base.Add(time.Second))
	if !s.HeaderComplete() {
		t.Error("CRLFCRLF split across read boundaries must still complete the header")
	}
}

func TestSlowLorisEmptyFeedIsInert(t *testing.T) {
	s := &SlowLorisScanner{}
	base := time.Unix(1000, 0)
	s.Feed(nil, base)
	s.Feed([]byte{}, base)
	if s.started || s.SlowRequest(base.Add(time.Hour), time.Second, 8192) {
		t.Error("empty feeds must not start the timer or flag anything")
	}
}
