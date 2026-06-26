// arena/gate — the public challenge-gate: serve a PoW challenge and verify a solve, on OWNED infra only.
// Reuses the evaders/pow primitives (anubis/friendlycaptcha/altcha families); never a third-party endpoint.

// The arena is the live-site, self-contained reproduction of documented OPEN web challenge mechanisms. A
// visitor brings any client (browser, script, bot), requests a challenge here, and tries to pass — while
// Kitsune's detector independently scores the same client over the edge. The gate verdict (did you solve the
// PoW?) and the detector verdict (does your client cohere?) are orthogonal and join client-side on ks_sid:
// a no-browser solver can pass the PoW AND still be convicted on the network layer — the demo the lab exists
// to show (a cost gate is not a bot/human discriminator). This package is production (separate from the
// red-team evaders/pow testbed); it imports the pow PRIMITIVES but ships its own HTTP surface.

package arena

import (
	"encoding/json"
	"net/http"
	"strconv"

	pow "github.com/datascry/kitsune/evaders/pow"
)

// MaxDifficulty caps the client-requestable difficulty so a hostile query value can't ask the gate to mint
// an absurd puzzle (the per-class defaults below are the norm; this is only the upper bound).
const MaxDifficulty = 26

func classOf(s string) pow.Class {
	switch s {
	case "many-small":
		return pow.ClassManySmall
	case "memory-hard":
		return pow.ClassMemoryHard
	default:
		return pow.ClassHashcash
	}
}

// NewMux builds the arena gate HTTP surface under /arena/*, signing tokens with secret and tracking issued
// nonces for single-use (replay) resistance. The challenge wire format is the pow.Challenge JSON the
// reference solver already understands; verify returns {ok, token}.
func NewMux(secret []byte) http.Handler {
	store := pow.NewNonceStore()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /arena/challenge", func(w http.ResponseWriter, r *http.Request) {
		class := classOf(r.URL.Query().Get("gate"))
		// Per-class defaults: SHA-256 classes can afford a high bit-target; memory-hard uses a LOW target
		// because each Argon2id evaluation is ~1000x costlier than a SHA-256 hash (so a low target still costs).
		diff := 20
		count := 16 // friendlycaptcha-style sub-puzzle count
		var memKiB uint32 = 8192
		if class == pow.ClassMemoryHard {
			diff = 8
		}
		if v := r.URL.Query().Get("difficulty"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= MaxDifficulty {
				diff = n
			}
		}
		c, err := pow.Mint(class, diff, count, memKiB, 1)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		store.Issue(c)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c)
	})

	mux.HandleFunc("POST /arena/verify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			pow.Challenge
			Counters []uint64 `json:"counters"`
		}
		// Bound the request body so a hostile client can't stream an unbounded payload at the gate.
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		c, sol := body.Challenge, pow.Solution{Counters: body.Counters}
		token, ok := pow.CheckSolution(secret, c, sol)
		// Single-use: the nonce must be outstanding at >= the claimed difficulty, then it is consumed, so a
		// solver cannot replay a token or downgrade the difficulty.
		if ok {
			ok = store.Redeem(c.Nonce, c.Difficulty)
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"ok": ok, "gate": string(c.Class)}
		if ok {
			resp["token"] = token
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("GET /arena/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	return mux
}
