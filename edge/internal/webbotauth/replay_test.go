// edge/webbotauth/replay_test — exercise the Web Bot Auth nonce ReplayStore.
// Asserts an in-window nonce reuse is flagged, while fresh / blank / expired-window nonces are not.

package webbotauth

import (
	"testing"
	"time"
)

func TestReplayStore(t *testing.T) {
	s := NewReplayStore()
	now := time.Unix(1_000_000, 0)
	exp := now.Unix() + 3600

	// A fresh nonce is not a replay; the SAME nonce within the window is.
	if s.Replay("k1", "n1", exp, now) {
		t.Fatal("first sighting of a nonce must not be a replay")
	}
	if !s.Replay("k1", "n1", exp, now) {
		t.Fatal("re-presenting the same in-window nonce must be a replay")
	}

	// A different keyid with the same nonce string is independent (per-signer uniqueness).
	if s.Replay("k2", "n1", exp, now) {
		t.Fatal("same nonce under a different keyid must not be a replay")
	}

	// A blank nonce is untrackable and never a replay, however many times it appears.
	if s.Replay("k1", "", exp, now) || s.Replay("k1", "", exp, now) {
		t.Fatal("a blank nonce must never be treated as a replay")
	}
}

func TestReplayStoreEvictsExpired(t *testing.T) {
	s := NewReplayStore()
	t0 := time.Unix(2_000_000, 0)
	exp := t0.Unix() + 100

	if s.Replay("k", "n", exp, t0) {
		t.Fatal("first sighting must not be a replay")
	}
	// After the window has passed, the entry is evicted, so a later sighting of the same nonce is NOT a
	// replay (an out-of-window signature is convicted by the separate expiry/forgery check, not here).
	later := time.Unix(exp+1, 0)
	if s.Replay("k", "n", exp, later) {
		t.Fatal("a sighting after the window must not be a replay (the entry was evicted)")
	}
}
