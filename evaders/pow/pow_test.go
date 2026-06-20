// evaders/pow/pow_test — assert each PoW class mints, solves and verifies, and rejects a bad solution.
// Guards the work functions (hashcash · many-small · memory-hard) the arms-race testbed depends on.

package pow

import "testing"

func TestSolveVerifyEachClass(t *testing.T) {
	cases := []struct {
		name string
		c    Challenge
	}{
		{"hashcash", mustMint(t, ClassHashcash, 12, 0, 0, 0)},
		{"many-small", mustMint(t, ClassManySmall, 8, 5, 0, 0)},
		{"memory-hard", mustMint(t, ClassMemoryHard, 6, 0, 1024, 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sol, evals := Solve(tc.c)
			if evals == 0 {
				t.Fatal("no work performed")
			}
			if !Verify(tc.c, sol) {
				t.Fatalf("solved solution does not verify for %s", tc.name)
			}
		})
	}
}

func TestManySmallHasOneCounterPerPuzzle(t *testing.T) {
	c := mustMint(t, ClassManySmall, 8, 7, 0, 0)
	sol, _ := Solve(c)
	if len(sol.Counters) != 7 {
		t.Fatalf("want 7 counters, got %d", len(sol.Counters))
	}
}

func TestVerifyRejectsWrongSolution(t *testing.T) {
	c := mustMint(t, ClassHashcash, 16, 0, 0, 0)
	if Verify(c, Solution{Counters: []uint64{0}}) {
		// counter 0 solving a 16-bit target is astronomically unlikely; a wrong solution must reject.
		t.Fatal("verify accepted an unsolved counter")
	}
	if Verify(c, Solution{Counters: []uint64{}}) {
		t.Fatal("verify accepted a length-mismatched solution")
	}
}

func TestHigherDifficultyCostsMore(t *testing.T) {
	_, easy := Solve(mustMint(t, ClassHashcash, 8, 0, 0, 0))
	_, hard := Solve(mustMint(t, ClassHashcash, 16, 0, 0, 0))
	if hard <= easy {
		t.Fatalf("expected 16-bit (%d evals) to cost more than 8-bit (%d evals)", hard, easy)
	}
}

func mustMint(t *testing.T, class Class, diff, count int, mem, tc uint32) Challenge {
	t.Helper()
	c, err := Mint(class, diff, count, mem, tc)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
