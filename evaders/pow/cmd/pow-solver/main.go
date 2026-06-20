// evaders/pow/cmd/pow-solver — the RED PoW evader: a native (no-browser) solver across every PoW class.
// Sweeps the cost asymmetry per class (BENCH=1), or beats the live gate end-to-end and redeems the token.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	pow "github.com/datascry/kitsune/evaders/pow"
)

// bench measures the native solve cost per CLASS — the cost-asymmetry that decides whether a class is a
// free pass for a headless scraper (fast SHA-256) or actually levels the field (memory-hard Argon2id).
func bench() {
	type row struct {
		label string
		c     pow.Challenge
	}
	must := func(c pow.Challenge, err error) pow.Challenge {
		if err != nil {
			log.Fatal(err)
		}
		return c
	}
	rows := []row{
		{"hashcash/d20", must(pow.Mint(pow.ClassHashcash, 20, 0, 0, 0))},
		{"hashcash/d22", must(pow.Mint(pow.ClassHashcash, 22, 0, 0, 0))},
		{"many-small/16x12", must(pow.Mint(pow.ClassManySmall, 12, 16, 0, 0))},
		{"memory-hard/d8/8MiB", must(pow.Mint(pow.ClassMemoryHard, 8, 0, 8192, 1))},
		{"memory-hard/d10/8MiB", must(pow.Mint(pow.ClassMemoryHard, 10, 0, 8192, 1))},
	}
	fmt.Println("class\tevals\tsolve_ms\tevals_per_sec")
	for _, r := range rows {
		start := time.Now()
		_, evals := pow.Solve(r.c)
		ms := time.Since(start).Seconds() * 1000
		eps := float64(evals) / (ms / 1000)
		fmt.Printf("%s\t%d\t%.1f\t%.0f\n", r.label, evals, ms, eps)
	}
}

// solveLive runs the full evasion against the live gate for one class: GET /challenge, brute-force, POST
// /verify with the full challenge + counters, and report whether the no-browser solver got the pass token.
func solveLive(gate, class string) {
	resp, err := http.Get(gate + "/challenge?class=" + class) //nolint:noctx
	if err != nil {
		log.Fatal(err)
	}
	var c pow.Challenge
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		log.Fatal(err)
	}
	resp.Body.Close()

	start := time.Now()
	sol, evals := pow.Solve(c)
	solveMs := time.Since(start).Seconds() * 1000

	// POST the full challenge (so the gate knows the class/params) plus the solving counters.
	out := map[string]any{
		"class": c.Class, "nonce": c.Nonce, "difficulty": c.Difficulty,
		"count": c.Count, "mem_kib": c.MemKiB, "time_cost": c.TimeCost,
		"counters": sol.Counters,
	}
	payload, _ := json.Marshal(out)
	vr, err := http.Post(gate+"/verify", "application/json", bytes.NewReader(payload)) //nolint:noctx
	if err != nil {
		log.Fatal(err)
	}
	body, _ := io.ReadAll(vr.Body)
	vr.Body.Close()
	var got struct {
		OK    bool   `json:"ok"`
		Token string `json:"token"`
	}
	_ = json.Unmarshal(body, &got)

	rec := map[string]any{
		"mode": "pow-solver", "class": string(c.Class), "difficulty": c.Difficulty,
		"evals": evals, "solve_ms": solveMs, "passed": got.OK, "has_token": got.Token != "",
	}
	j, _ := json.Marshal(rec)
	fmt.Println("__KS__" + string(j))
	log.Printf("class=%s solved in %.1f ms (%d evals) -> passed=%v", c.Class, solveMs, evals, got.OK)
}

func main() {
	if os.Getenv("BENCH") == "1" {
		bench()
		return
	}
	gate := os.Getenv("POW_GATE")
	if gate == "" {
		gate = "http://pow-gate:8090"
	}
	class := os.Getenv("POW_CLASS")
	if class == "" {
		class = "hashcash"
	}
	// Optional: hammer the gate N times to show a fleet pays the cost per session (the coordination angle).
	n := 1
	if v := os.Getenv("POW_ROUNDS"); v != "" {
		if k, err := strconv.Atoi(v); err == nil && k > 0 {
			n = k
		}
	}
	for i := 0; i < n; i++ {
		solveLive(gate, class)
	}
}
