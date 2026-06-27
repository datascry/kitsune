// arena/rate_test — the token-bucket rate gate: bucket refill math, client keying, and the 200/429 HTTP knee.
// Asserts the per-level RPS budget (cost dial) and that a burst above it trips the 429 knee the RPS scout finds.

package arena

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTokenBucketAllowsBurstThenDenies(t *testing.T) {
	rl := newRateLimiter(5, 5) // 5 rps, burst 5
	t0 := time.Unix(1000, 0)
	for i := 0; i < 5; i++ {
		if !rl.allow("k", t0) {
			t.Fatalf("request %d within burst should be allowed", i)
		}
	}
	if rl.allow("k", t0) {
		t.Fatal("6th request at the same instant should be denied (bucket empty)")
	}
}

func TestTokenBucketRefills(t *testing.T) {
	rl := newRateLimiter(5, 5)
	t0 := time.Unix(2000, 0)
	for i := 0; i < 5; i++ {
		rl.allow("k", t0) // drain
	}
	if rl.allow("k", t0) {
		t.Fatal("drained bucket must deny")
	}
	if !rl.allow("k", t0.Add(time.Second)) { // 1s later → +5 tokens
		t.Fatal("after a 1s refill the bucket should allow again")
	}
}

func TestTokenBucketIsPerClient(t *testing.T) {
	rl := newRateLimiter(1, 1)
	t0 := time.Unix(3000, 0)
	if !rl.allow("a", t0) || !rl.allow("b", t0) {
		t.Fatal("distinct clients have independent buckets")
	}
	if rl.allow("a", t0) {
		t.Fatal("client a's bucket is now empty")
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/arena/rate", nil)
	r.RemoteAddr = "1.2.3.4:5678"
	if got := clientIP(r); got != "1.2.3.4" {
		t.Errorf("RemoteAddr host = %q", got)
	}
	r.Header.Set("X-Forwarded-For", "9.8.7.6, 10.0.0.1")
	if got := clientIP(r); got != "9.8.7.6" {
		t.Errorf("XFF client = %q", got)
	}
}

func TestRateGateReturns429AboveBudget(t *testing.T) {
	srv := httptest.NewServer(NewMux([]byte("secret")))
	defer srv.Close()
	// hard level = 5 rps / burst 5; a fast burst of 12 from one client must yield some 200s then a 429.
	var ok, throttled int
	for i := 0; i < 12; i++ {
		resp, err := http.Get(srv.URL + "/arena/rate?level=hard")
		if err != nil {
			t.Fatal(err)
		}
		switch resp.StatusCode {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			throttled++
		}
		_ = resp.Body.Close()
	}
	if ok == 0 {
		t.Error("the first requests within the burst should be 200")
	}
	if throttled == 0 {
		t.Error("a 12-request burst at the hard budget (5 rps) should trip a 429 knee")
	}
}

func TestRateParamsScaleByLevel(t *testing.T) {
	easy, _ := rateParams(LevelEasy)
	hard, _ := rateParams(LevelHard)
	if !(easy > hard) {
		t.Fatalf("easy budget (%v) must exceed hard (%v) — the cost dial", easy, hard)
	}
}
