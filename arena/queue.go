// arena/queue — a virtual waiting-room / queue gate (Queue-it / Cloudflare Waiting Room family, owned infra).
// Issues a position ticket, admits after a controlled wait, and measures the SERVER-OBSERVED admission->action time.

package arena

import (
	"sync"
	"time"
)

// queueTicket is one client's position in the virtual queue. admitAfter is the controlled wait (a per-level COST
// dial). The ADMISSION instant is canonical (issuedAt+admitAfter) — the server decides it, so the client cannot
// backdate it; the admission->action time measured at /act is the unforgeable wait-behaviour signal.
type queueTicket struct {
	issuedAt   time.Time
	admitAfter time.Duration
	position   int
}

// queueStore holds issued, not-yet-acted queue tickets (single-use at /act). Safe for concurrent use. Mirrors
// captchaStore's shape; keyed by an opaque ticket id.
type queueStore struct {
	mu      sync.Mutex
	tickets map[string]*queueTicket
	served  int // running admit count = the next position handed out
}

func newQueueStore() *queueStore { return &queueStore{tickets: map[string]*queueTicket{}} }

// issue mints a ticket at the back of the queue with the given admit delay, returning its position.
func (s *queueStore) issue(id string, admitAfter time.Duration, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.served++
	s.tickets[id] = &queueTicket{issuedAt: now, admitAfter: admitAfter, position: s.served}
	return s.served
}

// status reports whether the wait has elapsed (the client is admitted). ok=false for an unknown ticket.
func (s *queueStore) status(id string, now time.Time) (admitted bool, position int, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tickets[id]
	if !ok {
		return false, 0, false
	}
	return !now.Before(t.issuedAt.Add(t.admitAfter)), t.position, true
}

// act consumes an admitted ticket for the protected action. It returns the SERVER-OBSERVED admission->action
// elapsed (now minus the canonical admission instant issuedAt+admitAfter). admitted=false means the client
// acted BEFORE its wait elapsed (a queue bypass — it never really waited); ok=false is an unknown/used ticket.
func (s *queueStore) act(id string, now time.Time) (elapsed time.Duration, admitted, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, exists := s.tickets[id]
	if !exists {
		return 0, false, false
	}
	admitTime := t.issuedAt.Add(t.admitAfter)
	if now.Before(admitTime) {
		return 0, false, true // acted before admission — the client skipped the wait
	}
	delete(s.tickets, id) // single-use
	return now.Sub(admitTime), true, true
}
