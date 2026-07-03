// arena/gate_test — assert the public gate issues a solvable challenge, accepts a real solve, and is single-use.
// Guards the BLUE-side replay resistance + token integrity the live arena depends on.

package arena

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

func TestCaptchaFlagsSubHumanSolveSpeed(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	// Fetch a math captcha and compute its answer.
	resp, err := http.Get(srv.URL + "/arena/captcha?kind=math")
	if err != nil {
		t.Fatal(err)
	}
	var ch struct{ ID, Prompt string }
	if err := json.NewDecoder(resp.Body).Decode(&ch); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	f := strings.Fields(strings.TrimSuffix(strings.TrimPrefix(ch.Prompt, "What is "), "?")) // "A <op> B"
	if len(f) != 3 {
		t.Fatalf("unexpected math prompt %q", ch.Prompt)
	}
	a, _ := strconv.Atoi(f[0])
	b, _ := strconv.Atoi(f[2])
	ans := a + b
	switch f[1] {
	case "-":
		ans = a - b
	case "+":
		ans = a + b
	default: // × or *
		ans = a * b
	}
	// Verify INSTANTLY (sub-human speed): the correct answer must PASS the gate AND raise the anomaly — no human
	// perceives+answers in ~0 ms. A slow human solve stays silent (grounded live at solve_ms 1306, no anomaly).
	body, _ := json.Marshal(map[string]any{"kind": "math", "id": ch.ID, "answer": strconv.Itoa(ans)})
	vr, err := http.Post(srv.URL+"/arena/captcha/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer vr.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(vr.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["ok"] != true {
		t.Fatalf("instant correct solve should pass the gate: %v", out)
	}
	if out["anomaly"] != "solved_faster_than_human" {
		t.Fatalf("a sub-human-speed solve must be flagged, got: %v", out)
	}
}

func TestSliderFlagsTrajectoryExceedingSolveTime(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/arena/slider?level=easy")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		ID   string  `json:"id"`
		GapX float64 `json:"gap_x"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	g := s.GapX
	// A valid, variable-velocity drag that CLAIMS a 2000ms duration, ending at the gap.
	traj := []map[string]float64{
		{"t": 0, "x": 0}, {"t": 250, "x": g * 0.10}, {"t": 600, "x": g * 0.32}, {"t": 950, "x": g * 0.56},
		{"t": 1300, "x": g * 0.76}, {"t": 1650, "x": g * 0.90}, {"t": 1850, "x": g * 0.97}, {"t": 2000, "x": g},
	}
	// Submit INSTANTLY: the 2000ms claimed drag exceeds the ~0ms server-observed solve => synthetic trajectory.
	body, _ := json.Marshal(map[string]any{"id": s.ID, "x": g, "trajectory": traj})
	vr, err := http.Post(srv.URL+"/arena/slider/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer vr.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(vr.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["ok"] != true {
		t.Fatalf("a valid drag to the gap should pass: %v", out)
	}
	if out["anomaly"] != "trajectory_exceeds_solve_time" {
		t.Fatalf("a trajectory claiming more drag-time than the whole solve must be flagged: %v", out)
	}
}

func TestRotateFlagsTrajectoryExceedingSolveTime(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/arena/rotate?level=easy")
	if err != nil {
		t.Fatal(err)
	}
	var rc struct {
		ID    string  `json:"id"`
		Angle float64 `json:"angle"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rc); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	a := rc.Angle
	// A valid, variable-velocity rotation from the initial angle down to upright (0), CLAIMING a 2000ms drag.
	traj := []map[string]float64{
		{"t": 0, "angle": a}, {"t": 250, "angle": a * 0.88}, {"t": 600, "angle": a * 0.66}, {"t": 950, "angle": a * 0.44},
		{"t": 1300, "angle": a * 0.24}, {"t": 1650, "angle": a * 0.10}, {"t": 1850, "angle": a * 0.03}, {"t": 2000, "angle": 0},
	}
	body, _ := json.Marshal(map[string]any{"id": rc.ID, "trajectory": traj})
	vr, err := http.Post(srv.URL+"/arena/rotate/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer vr.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(vr.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["ok"] != true {
		t.Fatalf("a valid rotation to upright should pass: %v", out)
	}
	if out["anomaly"] != "trajectory_exceeds_solve_time" {
		t.Fatalf("a rotation trajectory claiming more time than the whole solve must be flagged: %v", out)
	}
}
