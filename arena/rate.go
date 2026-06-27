// arena/rate — a token-bucket rate-limit gate (the documented CDN/WAF rate-limit mechanism).
// /arena/rate returns 200 under the per-level RPS budget, 429 above it — a rate-based challenge for RPS recon.

package arena

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// rateParams is the cost dial for the rate gate: requests/sec budget + burst per client. Harder = tighter
// budget (a smaller RPS allowance before 429), never a better bot/human test — the detector discriminates.
func rateParams(lv Level) (limit float64, burst int) {
	switch lv {
	case LevelEasy:
		return 50, 50
	case LevelHard:
		return 5, 5
	default:
		return 20, 20
	}
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// rateLimiter is a per-client token bucket: each client IP gets `burst` tokens that refill at `limit`/sec; a
// request that finds an empty bucket is over the rate budget. The standard leaky/token-bucket limiter a CDN runs.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	limit   float64
	burst   int
}

func newRateLimiter(limit float64, burst int) *rateLimiter {
	return &rateLimiter{buckets: map[string]*tokenBucket{}, limit: limit, burst: burst}
}

// allow consumes one token for key at time now, refilling first; false means the client is over its RPS budget.
func (rl *rateLimiter) allow(key string, now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b := rl.buckets[key]
	if b == nil {
		b = &tokenBucket{tokens: float64(rl.burst), last: now}
		rl.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * rl.limit
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// clientIP keys the bucket by the originating address — the proxy-forwarded client if present, else RemoteAddr
// (host part only). A fleet behind one egress shares a bucket, which is the point: the rate budget is per-origin.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host
}
