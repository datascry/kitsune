// evaders/pow/gate_test — assert the gate signs a token only for a valid solve and enforces single-use nonces.
// Guards the BLUE-side replay resistance + token integrity the solver must actually defeat.

package pow

import "testing"

func TestCheckSolutionSignsOnlyValidSolve(t *testing.T) {
	secret := []byte("test-secret")
	c := mustMint(t, ClassHashcash, 12, 0, 0, 0)
	sol, _ := Solve(c)
	token, ok := CheckSolution(secret, c, sol)
	if !ok || token == "" {
		t.Fatal("valid solve was not accepted / signed")
	}
	if _, ok := CheckSolution(secret, c, Solution{Counters: []uint64{0}}); ok {
		t.Fatal("an unsolved counter was accepted")
	}
}

func TestNonceStoreIsSingleUse(t *testing.T) {
	s := NewNonceStore()
	c := mustMint(t, ClassHashcash, 8, 0, 0, 0)
	s.Issue(c)
	if !s.Redeem(c.Nonce, c.Difficulty) {
		t.Fatal("first redeem of an issued nonce should succeed")
	}
	if s.Redeem(c.Nonce, c.Difficulty) {
		t.Fatal("second redeem must fail (replay)")
	}
}

func TestInstrumentedBlocksNaiveButNotForgery(t *testing.T) {
	secret := []byte("test-secret")
	c, err := Mint(ClassHashcash, 12, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	c.Instrumented = true
	sol, _ := Solve(c)
	// Naive no-browser solver: no realm proof → blocked (this is the win over a raw PoW gate).
	if _, ok := CheckInstrumented(secret, c, sol, RealmProof{}); ok {
		t.Fatal("instrumented gate accepted a solve with no realm proof")
	}
	// A main-realm-only spoof: realms diverge → blocked.
	if _, ok := CheckInstrumented(secret, c, sol, RealmProof{Main: "a", Worker: "b"}); ok {
		t.Fatal("instrumented gate accepted a divergent realm proof")
	}
	// Forging solver: two EQUAL fabricated hashes → passes. A client-asserted proof is forgeable, so robust
	// instrumentation must be server-OBSERVED (Kitsune's collector), not client-submitted.
	if _, ok := CheckInstrumented(secret, c, sol, RealmProof{Main: "x", Worker: "x"}); !ok {
		t.Fatal("forged equal realm proof should pass a client-side check (the grounded weakness)")
	}
}

func TestNonceStoreRemembersInstrumented(t *testing.T) {
	s := NewNonceStore()
	c, _ := Mint(ClassHashcash, 8, 0, 0, 0)
	c.Instrumented = true
	s.Issue(c)
	_, instrumented, ok := s.Peek(c.Nonce)
	if !ok || !instrumented {
		t.Fatal("Peek should report the issued instrumented flag")
	}
}

func TestRedeemRejectsUnknownAndDowngrade(t *testing.T) {
	s := NewNonceStore()
	if s.Redeem("never-issued", 20) {
		t.Fatal("redeeming an unknown nonce must fail")
	}
	c := mustMint(t, ClassHashcash, 20, 0, 0, 0)
	s.Issue(c)
	if s.Redeem(c.Nonce, 10) {
		t.Fatal("redeeming below the issued difficulty must fail (downgrade attack)")
	}
}
