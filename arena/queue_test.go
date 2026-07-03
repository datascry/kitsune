// arena/queue_test — the virtual-queue store: admission gates on the controlled wait, /act measures the
// server-observed admission->action elapsed, acting before admission is a bypass, and a ticket is single-use.

package arena

import (
	"testing"
	"time"
)

func TestQueueAdmissionAndAction(t *testing.T) {
	s := newQueueStore()
	t0 := time.Now()
	if pos := s.issue("tk", time.Second, t0); pos != 1 {
		t.Fatalf("first ticket position = %d, want 1", pos)
	}

	// Before the wait elapses: not admitted, and acting is a bypass (admitted=false).
	if admitted, _, _ := s.status("tk", t0.Add(500*time.Millisecond)); admitted {
		t.Fatal("admitted before the wait elapsed")
	}
	if _, admitted, ok := s.act("tk", t0.Add(500*time.Millisecond)); !ok || admitted {
		t.Fatalf("act before admission: admitted=%v ok=%v — want a known-but-not-admitted bypass", admitted, ok)
	}

	// After the wait: admitted, and /act returns the exact admission->action elapsed (act - (issued+wait)).
	if admitted, _, _ := s.status("tk", t0.Add(1500*time.Millisecond)); !admitted {
		t.Fatal("not admitted after the wait elapsed")
	}
	elapsed, admitted, ok := s.act("tk", t0.Add(1500*time.Millisecond))
	if !ok || !admitted || elapsed != 500*time.Millisecond {
		t.Fatalf("act after admission: elapsed=%v admitted=%v ok=%v — want 500ms/true/true", elapsed, admitted, ok)
	}

	// Single-use: the ticket is consumed, so a second act fails as unknown.
	if _, _, ok := s.act("tk", t0.Add(1600*time.Millisecond)); ok {
		t.Fatal("queue ticket was not single-use")
	}
	if _, _, ok := s.act("never-issued", t0); ok {
		t.Fatal("an unknown ticket must not act")
	}
}
