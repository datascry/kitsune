// evaders/pow/gate — the BLUE side: issue PoW challenges and mint an HMAC-signed pass token on a valid solve.
// A single-use nonce store + signed token make it a real anti-bot gate the solver must actually beat.

package pow

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
)

// SignToken returns an HMAC-SHA256 token binding a SOLVED challenge to the gate's secret — the proof a
// client presents to pass. A client that did not solve the PoW cannot forge it (it never sees the secret).
func SignToken(secret []byte, c Challenge, s Solution) string {
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "%s:%s:%d:%v", c.Class, c.Nonce, c.Difficulty, s.Counters)
	return hex.EncodeToString(mac.Sum(nil))
}

// NonceStore tracks issued, not-yet-redeemed nonces so each challenge passes the gate at most once
// (replay resistance — the mCaptcha/anubis single-use property). Safe for concurrent use.
type NonceStore struct {
	mu     sync.Mutex
	issued map[string]int // nonce -> difficulty it was issued at
}

// NewNonceStore returns an empty single-use nonce store.
func NewNonceStore() *NonceStore { return &NonceStore{issued: map[string]int{}} }

// Issue records a freshly minted challenge as outstanding.
func (s *NonceStore) Issue(c Challenge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issued[c.Nonce] = c.Difficulty
}

// Redeem consumes a nonce if it is outstanding and was issued at >= the claimed difficulty, returning
// false for an unknown, already-redeemed, or under-difficulty nonce (so a solver cannot downgrade it).
func (s *NonceStore) Redeem(nonce string, difficulty int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.issued[nonce]
	if !ok || difficulty < d {
		return false
	}
	delete(s.issued, nonce)
	return true
}

// CheckSolution verifies the solution solves the challenge; on success returns the signed pass token.
func CheckSolution(secret []byte, c Challenge, s Solution) (string, bool) {
	if !Verify(c, s) {
		return "", false
	}
	return SignToken(secret, c, s), true
}
