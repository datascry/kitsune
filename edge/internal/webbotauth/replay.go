// edge/webbotauth/replay — single-use nonce tracking for Web Bot Auth (RFC 9421) signatures.
// Flags an in-window nonce reuse as a captured-credential replay (the expiry check structurally misses it).

package webbotauth

import (
	"sync"
	"time"
)

// defaultTTL bounds a valid signature that carries no explicit expires (out-of-spec but possible) so the
// seen-set cannot grow without limit on such inputs.
const defaultTTL = 1800 // seconds

// ReplayStore tracks the (keyid, nonce) pairs of VALID Web Bot Auth signatures so an in-window REUSE — a
// captured-credential replay that still passes the created/expires window the G25 forgery check enforces —
// is caught. RFC 9421 requires a nonce to be unique within the validity window, so a real signer never
// repeats one: the structure is FP-safe by construction. Entries self-evict at the signature's own expiry,
// so the live set stays bounded.
type ReplayStore struct {
	mu   sync.Mutex
	seen map[string]int64 // keyid\x00nonce -> expiry (unix seconds)
}

// NewReplayStore returns an empty store.
func NewReplayStore() *ReplayStore {
	return &ReplayStore{seen: map[string]int64{}}
}

// Replay records a valid signature's nonce and reports whether that nonce was ALREADY seen for this keyid
// within its window — i.e. a replay. A blank nonce is untrackable (the draft says nonce SHOULD be present),
// so it is never treated as a replay. Expired entries are swept on each call (the live set is small).
func (s *ReplayStore) Replay(keyid, nonce string, expires int64, now time.Time) bool {
	if nonce == "" {
		return false
	}
	nowU := now.Unix()
	ttl := expires
	if ttl <= 0 {
		ttl = nowU + defaultTTL
	}
	key := keyid + "\x00" + nonce
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.seen {
		if exp <= nowU {
			delete(s.seen, k)
		}
	}
	if _, ok := s.seen[key]; ok {
		return true
	}
	s.seen[key] = ttl
	return false
}
