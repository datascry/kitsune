// evaders/pow/gate — the BLUE side: issue PoW challenges and mint an HMAC-signed pass token on a valid solve.
// A single-use nonce store + signed token + an OPTIONAL instrumented (cap-style) browser-proof gate.

package pow

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
)

// RealmProof is a client-asserted browser-execution proof (the cap-style instrumentation): the hash of a
// nonce'd canvas/realm draw computed in the MAIN thread and in a WORKER. A real browser produces two EQUAL
// non-trivial hashes (one rasterizer); a main-realm-only spoof diverges. CRUCIAL CAVEAT (grounded iter-63):
// because the client ASSERTS both values, a no-browser solver simply submits Main == Worker == anything and
// passes — a client-side proof is forgeable, so robust instrumentation must be SERVER-OBSERVED (Kitsune's
// collector, where the detector independently sees the worker), not client-submitted.
type RealmProof struct {
	Main   string `json:"realm_main"`
	Worker string `json:"realm_worker"`
}

// coherent reports whether the proof is structurally a real-browser realm proof (non-empty + the realms
// agree). This is all a gate can check on a CLIENT-ASSERTED proof — and exactly why it is forgeable.
func (p RealmProof) coherent() bool {
	return p.Main != "" && p.Main == p.Worker
}

// SignToken returns an HMAC-SHA256 token binding a SOLVED challenge to the gate's secret — the proof a
// client presents to pass. A client that did not solve the PoW cannot forge it (it never sees the secret).
func SignToken(secret []byte, c Challenge, s Solution) string {
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "%s:%s:%d:%v", c.Class, c.Nonce, c.Difficulty, s.Counters)
	return hex.EncodeToString(mac.Sum(nil))
}

type record struct {
	difficulty   int
	instrumented bool
}

// NonceStore tracks issued, not-yet-redeemed nonces so each challenge passes the gate at most once
// (replay resistance — the mCaptcha/anubis single-use property). Safe for concurrent use.
type NonceStore struct {
	mu     sync.Mutex
	issued map[string]record
}

// NewNonceStore returns an empty single-use nonce store.
func NewNonceStore() *NonceStore { return &NonceStore{issued: map[string]record{}} }

// Issue records a freshly minted challenge as outstanding.
func (s *NonceStore) Issue(c Challenge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issued[c.Nonce] = record{c.Difficulty, c.Instrumented}
}

// Peek reports a nonce's issued difficulty + whether it requires the instrumented proof, without consuming
// it — so /verify can decide which check to apply before redeeming.
func (s *NonceStore) Peek(nonce string) (difficulty int, instrumented bool, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.issued[nonce]
	return r.difficulty, r.instrumented, ok
}

// Redeem consumes a nonce if it is outstanding and was issued at >= the claimed difficulty, returning
// false for an unknown, already-redeemed, or under-difficulty nonce (so a solver cannot downgrade it).
func (s *NonceStore) Redeem(nonce string, difficulty int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.issued[nonce]
	if !ok || difficulty < r.difficulty {
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

// CheckInstrumented is CheckSolution PLUS the cap-style browser-proof check: the PoW must be solved AND the
// client-asserted realm proof must be coherent. It blocks the NAIVE no-browser solver (which submits no
// proof) but — as grounded — NOT a forging solver (which submits two equal fabricated hashes).
func CheckInstrumented(secret []byte, c Challenge, s Solution, p RealmProof) (string, bool) {
	if !Verify(c, s) || !p.coherent() {
		return "", false
	}
	return SignToken(secret, c, s), true
}
