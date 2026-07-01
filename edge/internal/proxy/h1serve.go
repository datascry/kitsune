// edge/proxy/h1serve — serve ALPN http/1.1 while teeing request-header bytes through a SlowLorisScanner.
// A connection held open on an incomplete header past a time/byte budget emits network.slow_http_attack.

package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
	"github.com/datascry/kitsune/edge/internal/peek"
	"github.com/datascry/kitsune/edge/internal/signal"
)

// The slowloris budget: a request header still incomplete after this long, on fewer than this many bytes, is
// a connection held open by a trickle of partial-header bytes rather than a legitimately slow (high-latency)
// but complete request. minAge sits below the server ReadTimeout so a held connection has aged past the
// budget by the time the server tears it down. Mirrors the values the scanner's own tests exercise.
const (
	slowHTTPMinAge   = 10 * time.Second
	slowHTTPMaxBytes = 8192
)

// slowConn tees every byte the HTTP/1.1 server reads into a SlowLorisScanner, timed by now. Like
// countingConn on the h2 path it returns the bytes unchanged (it only observes the header arrival), and it
// closes a channel on Close so the single-connection listener below can block until serving is done.
type slowConn struct {
	net.Conn
	scanner   *fingerprint.SlowLorisScanner
	now       func() time.Time
	closeOnce sync.Once
	closed    chan struct{}
}

func newSlowConn(c net.Conn, scanner *fingerprint.SlowLorisScanner, now func() time.Time) *slowConn {
	return &slowConn{Conn: c, scanner: scanner, now: now, closed: make(chan struct{})}
}

func (c *slowConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.scanner.Feed(p[:n], c.now())
	}
	return n, err
}

func (c *slowConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// errListenerDone ends the inner http.Server's accept loop once its single connection has been closed.
var errListenerDone = errors.New("edge: single-connection listener done")

// singleConnListener hands out one already-accepted connection, then blocks the next Accept until that
// connection is closed. Blocking (rather than erroring immediately) makes http.Server.Serve return only
// AFTER the connection is fully served, so the caller can inspect the post-close scanner state without a race.
type singleConnListener struct {
	conn   *slowConn
	handed bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.handed {
		l.handed = true
		return l.conn, nil
	}
	<-l.conn.closed
	return nil, errListenerDone
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// serveH1 is the ALPN "http/1.1" handler: it serves the connection normally (the full prepare()/forward
// pipeline runs for any COMPLETED request, exactly as the default h1 path) while a SlowLorisScanner watches
// the request-header bytes. When the connection is torn down (the server's ReadTimeout fires, or the client
// closes) with the header still incomplete and held past the budget, it attributes a slow-HTTP attack. Such a
// connection is sessionless — a pure slowloris never completes a request, so it carries no ks_sid — so the
// signal is minted under a synthetic session with the observed source IP, which lets the coordination scorer
// aggregate a slowloris FLEET as an L7 flood (the DoS tell corroborates the flood shape).
// serveConns is the edge's own accept loop. The stdlib http.Server refuses to hand off ALPN "http/1.1" via
// TLSNextProto (validNextProto reserves "http/1.1" and "" for its built-in h1 path), so the edge dispatches
// connections itself: h2 → serveH2, everything else → serveH1 (which tees the request-header bytes through the
// SlowLorisScanner). Each handler extracts its ClientHello from the peek.Conn directly, so no ConnContext is
// needed. A handshake deadline bounds a TLS-layer slowloris; per-request read deadlines are set by the h1/h2
// servers the handlers run.
func (p *ReverseProxy) serveConns(srv *http.Server, ln net.Listener) error { // pragma: integration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		tc, ok := c.(*tls.Conn)
		if !ok {
			_ = c.Close()
			continue
		}
		go p.dispatchConn(srv, tc)
	}
}

// dispatchConn completes the TLS handshake (bounded by the read timeout so a stalled handshake cannot pin a
// goroutine) and routes the connection by negotiated ALPN protocol.
func (p *ReverseProxy) dispatchConn(srv *http.Server, tc *tls.Conn) { // pragma: integration
	if srv.ReadTimeout > 0 {
		_ = tc.SetReadDeadline(p.now().Add(srv.ReadTimeout))
	}
	if err := tc.Handshake(); err != nil {
		_ = tc.Close()
		return
	}
	_ = tc.SetReadDeadline(time.Time{}) // clear; the h1/h2 servers set their own per-request deadlines
	if tc.ConnectionState().NegotiatedProtocol == "h2" {
		p.serveH2(srv, tc, p)
		return
	}
	p.serveH1(srv, tc, p)
}

func (p *ReverseProxy) serveH1(srv *http.Server, tc *tls.Conn, h http.Handler) { // pragma: integration
	ctx := context.Background()
	if pc, ok := tc.NetConn().(*peek.Conn); ok {
		ctx = context.WithValue(ctx, helloKey, pc.ClientHello())
	}
	scanner := &fingerprint.SlowLorisScanner{}
	sc := newSlowConn(tc, scanner, p.now)
	inner := &http.Server{
		Handler:     h,
		ReadTimeout: srv.ReadTimeout,
		ConnContext: func(context.Context, net.Conn) context.Context { return ctx },
	}
	// Blocks until the connection is served and closed (the listener's second Accept waits on sc.closed).
	_ = inner.Serve(&singleConnListener{conn: sc})
	if scanner.SlowRequest(p.now(), slowHTTPMinAge, slowHTTPMaxBytes) {
		p.emitSlowHTTP(connIP(tc))
	}
}

// emitSlowHTTP forwards a slow-HTTP (slowloris) attack signal under a freshly minted synthetic session id,
// tagged with the observed source IP. The synthetic id is because the held connection never completed a
// request (no ks_sid); pairing the DoS tell with observed_ip is what the coordination scorer folds into an
// L7-flood attribution when many such connections arrive from a fleet.
func (p *ReverseProxy) emitSlowHTTP(ip string) { // pragma: integration
	id, err := p.newID()
	if err != nil {
		return
	}
	now := p.now()
	sigs := []signal.Signal{signal.Network(id, "slow_http_attack", true, now)}
	if ip != "" {
		sigs = append(sigs, signal.Network(id, "observed_ip", ip, now))
	}
	p.forward(sigs)
}

// connIP is clientIP's connection-level twin: the source IP (without port) of a raw connection.
func connIP(c net.Conn) string {
	if c == nil || c.RemoteAddr() == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(c.RemoteAddr().String()); err == nil {
		return host
	}
	return ""
}
