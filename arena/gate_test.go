// arena/gate_test — assert the public gate issues a solvable challenge, accepts a real solve, and is single-use.
// Guards the BLUE-side replay resistance + token integrity the live arena depends on.

package arena

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	pow "github.com/datascry/kitsune/evaders/pow"
)

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(NewMux([]byte("test-secret-32-bytes-long-padxxx")))
}

func getChallenge(t *testing.T, srv *httptest.Server, gate string) pow.Challenge {
	t.Helper()
	resp, err := http.Get(srv.URL + "/arena/challenge?gate=" + gate + "&difficulty=8")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var c pow.Challenge
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		t.Fatal(err)
	}
	return c
}

func verify(t *testing.T, srv *httptest.Server, c pow.Challenge, counters []uint64) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"class": c.Class, "nonce": c.Nonce, "difficulty": c.Difficulty,
		"count": c.Count, "mem_kib": c.MemKiB, "time_cost": c.TimeCost, "counters": counters,
	})
	resp, err := http.Post(srv.URL+"/arena/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGateIssuesSolvableChallengeAndMintsToken(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	for _, gate := range []string{"hashcash", "many-small", "memory-hard"} {
		c := getChallenge(t, srv, gate)
		if string(c.Class) == "" || c.Nonce == "" {
			t.Fatalf("%s: empty challenge %+v", gate, c)
		}
		sol, _ := pow.Solve(c)
		out := verify(t, srv, c, sol.Counters)
		if out["ok"] != true {
			t.Fatalf("%s: a valid solve was rejected: %v", gate, out)
		}
		if _, hasTok := out["token"]; !hasTok {
			t.Fatalf("%s: no token minted on a valid solve", gate)
		}
	}
}

func TestGateRejectsBadSolution(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	c := getChallenge(t, srv, "hashcash")
	out := verify(t, srv, c, []uint64{0}) // counter 0 almost certainly does not solve
	if out["ok"] != false {
		t.Fatalf("a bogus solution was accepted: %v", out)
	}
}

func TestGateNonceIsSingleUse(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	c := getChallenge(t, srv, "hashcash")
	sol, _ := pow.Solve(c)
	if verify(t, srv, c, sol.Counters)["ok"] != true {
		t.Fatal("first redeem should pass")
	}
	if verify(t, srv, c, sol.Counters)["ok"] != false {
		t.Fatal("a replayed (already-redeemed) nonce must be rejected")
	}
}
