// evaders/pow/pow — multi-class proof-of-work primitive (anubis · friendlycaptcha · altcha families).
// Mint / brute-force / verify challenges across the catalogued PoW classes — the core of the arms-race testbed.

package pow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"

	"golang.org/x/crypto/argon2"
)

// Class is a PoW family from docs/catalog.md §6, each a DISTINCT work function the solver must evade:
//   - hashcash    (anubis):         SHA-256 leading-zero-bits over one puzzle — the ubiquitous embeddable PoW.
//   - many-small  (friendlycaptcha): Count independent LOW-difficulty hashcash puzzles — variance reduction.
//   - memory-hard (altcha):          Argon2id work function — MEMORY-bound, so a native CPU solver loses the
//     SHA-256 speed advantage that makes the other classes a free pass (resists GPU/ASIC; levels CPU vs browser).
//
// The cap-class (PoW FUSED with a browser-instrumentation challenge) is intentionally NOT a pure work
// function here: its tell is whether a real browser ran the challenge JS — a coherence signal, the on-thesis
// rung documented in the roadmap, not something a headless solver can brute-force.
type Class string

const (
	ClassHashcash   Class = "hashcash"
	ClassManySmall  Class = "many-small"
	ClassMemoryHard Class = "memory-hard"
)

// MaxManySmallCount bounds the many-small sub-puzzle count. friendlycaptcha-style variance-reduction sets
// use tens of puzzles; this cap sits far above any real challenge while making the puzzles() allocation
// provably bounded, so a malformed or hostile Challenge.Count (it arrives over JSON) cannot drive an
// unbounded allocation (CodeQL go/uncontrolled-allocation-size).
const MaxManySmallCount = 1024

// Challenge is one PoW puzzle (or puzzle-set). Difficulty is in leading-zero BITS of the work-function
// output (per sub-puzzle for many-small); Count is the sub-puzzle count; MemKiB/TimeCost are Argon2 costs.
type Challenge struct {
	Class      Class  `json:"class"`
	Nonce      string `json:"nonce"`
	Difficulty int    `json:"difficulty"`
	Count      int    `json:"count,omitempty"`
	MemKiB     uint32 `json:"mem_kib,omitempty"`
	TimeCost   uint32 `json:"time_cost,omitempty"`
	// Instrumented marks a cap-style challenge that also demands a client-asserted browser realm proof.
	Instrumented bool `json:"instrumented,omitempty"`
}

// Solution carries one solving counter per puzzle (length 1 for single-puzzle classes, Count for many-small).
type Solution struct {
	Counters []uint64 `json:"counters"`
}

// Mint creates a fresh challenge for the class with a random nonce. memKiB/timeCost apply to memory-hard;
// count applies to many-small (both ignored otherwise). Callers pick class-appropriate difficulties.
func Mint(class Class, difficulty, count int, memKiB, timeCost uint32) (Challenge, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return Challenge{}, err
	}
	c := Challenge{Class: class, Nonce: hex.EncodeToString(b), Difficulty: difficulty}
	switch class {
	case ClassManySmall:
		if count <= 0 {
			count = 1
		}
		if count > MaxManySmallCount {
			count = MaxManySmallCount
		}
		c.Count = count
	case ClassMemoryHard:
		if memKiB == 0 {
			memKiB = 1024
		}
		if timeCost == 0 {
			timeCost = 1
		}
		c.MemKiB, c.TimeCost = memKiB, timeCost
	}
	return c, nil
}

func leadingZeroBits(d []byte) int {
	n := 0
	for _, by := range d {
		if by == 0 {
			n += 8
			continue
		}
		n += bits.LeadingZeros8(by)
		break
	}
	return n
}

// workDigest evaluates the class's work function over (subNonce, counter) — the loop body both sides run.
func workDigest(c Challenge, subNonce string, counter uint64) []byte {
	nb, _ := hex.DecodeString(c.Nonce)
	salt := append([]byte(subNonce), nb...)
	buf := make([]byte, len(salt)+8)
	copy(buf, salt)
	binary.LittleEndian.PutUint64(buf[len(salt):], counter)
	if c.Class == ClassMemoryHard {
		// Argon2id: memory-bound, so a native CPU has no SHA-256 throughput edge over a browser's WASM.
		return argon2.IDKey(buf, nb, c.TimeCost, c.MemKiB, 1, 32)
	}
	d := sha256.Sum256(buf)
	return d[:]
}

// puzzles returns the (subNonce, difficulty) list for the challenge: one entry for single-puzzle classes,
// Count entries (distinct sub-nonces) for many-small.
func puzzles(c Challenge) []string {
	if c.Class == ClassManySmall {
		n := c.Count
		if n < 1 {
			n = 1
		}
		if n > MaxManySmallCount {
			n = MaxManySmallCount // bound the allocation; an over-range count is malformed (Verify then fails on length mismatch)
		}
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("%d:", i)
		}
		return out
	}
	return []string{""}
}

// Verify reports whether the solution solves every puzzle in the challenge at its difficulty.
func Verify(c Challenge, s Solution) bool {
	ps := puzzles(c)
	if len(s.Counters) != len(ps) {
		return false
	}
	for i, sub := range ps {
		if leadingZeroBits(workDigest(c, sub, s.Counters[i])) < c.Difficulty {
			return false
		}
	}
	return true
}

// Solve brute-forces a solution and returns it with the total number of work-function evaluations tried —
// the cost the red-team measures per class (cheap for SHA-256 classes, memory-bound for Argon2id).
func Solve(c Challenge) (Solution, uint64) {
	ps := puzzles(c)
	sol := Solution{Counters: make([]uint64, len(ps))}
	var evals uint64
	for i, sub := range ps {
		var counter uint64
		for {
			evals++
			if leadingZeroBits(workDigest(c, sub, counter)) >= c.Difficulty {
				sol.Counters[i] = counter
				break
			}
			counter++
		}
	}
	return sol, evals
}
