// evaders/pow/cmd/pow-gate — the BLUE PoW gate as an HTTP service (anubis-style challenge endpoint).
// GET /challenge issues a single-use puzzle; POST /verify checks a solution and mints an HMAC pass token.

package main

import (
	"crypto/rand"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"

	pow "github.com/datascry/kitsune/evaders/pow"
)

func main() {
	addr := os.Getenv("POW_ADDR")
	if addr == "" {
		addr = "0.0.0.0:8090"
	}
	defaultDifficulty := 20
	if v := os.Getenv("POW_DIFFICULTY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			defaultDifficulty = n
		}
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatal(err)
	}
	store := pow.NewNonceStore()

	// Per-class default difficulties: SHA-256 classes can afford a high bit-target; the memory-hard class
	// uses a LOW bit-target because each Argon2id evaluation is ~1000x costlier than a SHA-256 hash.
	classOf := func(s string) pow.Class {
		switch s {
		case "many-small":
			return pow.ClassManySmall
		case "memory-hard":
			return pow.ClassMemoryHard
		default:
			return pow.ClassHashcash
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/challenge", func(w http.ResponseWriter, r *http.Request) {
		class := classOf(r.URL.Query().Get("class"))
		diff := defaultDifficulty
		count := 16 // friendlycaptcha-style sub-puzzle count
		var memKiB uint32 = 8192
		if class == pow.ClassMemoryHard {
			diff = 8 // each Argon2id eval is expensive — keep the bit-target low
		}
		if v := r.URL.Query().Get("difficulty"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 30 {
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
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		var c pow.Challenge
		var sol pow.Solution
		var body struct {
			pow.Challenge
			Counters []uint64 `json:"counters"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		c, sol = body.Challenge, pow.Solution{Counters: body.Counters}
		token, ok := pow.CheckSolution(secret, c, sol)
		// Single-use: the nonce must be outstanding at >= the claimed difficulty, then it is consumed.
		if ok {
			ok = store.Redeem(c.Nonce, c.Difficulty)
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"ok": ok}
		if ok {
			resp["token"] = token
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("pow-gate listening on %s (default difficulty %d)", addr, defaultDifficulty)
	srv := &http.Server{Addr: addr, Handler: mux}
	log.Fatal(srv.ListenAndServe())
}
