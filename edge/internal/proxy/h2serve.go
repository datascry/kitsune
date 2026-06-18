// edge/proxy/h2serve — capture the HTTP/2 connection preface, then serve the connection normally.
// Tees the decrypted preface through the h2 parser so the Akamai fingerprint reaches the detector.

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"

	"golang.org/x/net/http2"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
	"github.com/datascry/kitsune/edge/internal/peek"
)

// prefaceConn wraps a net.Conn whose HTTP/2 client preface has already been read and fingerprinted.
// It replays the consumed preface bytes on Read so the wrapping http2 server still sees a complete
// connection — the same capture-and-replay trick peek.Conn uses for the TLS ClientHello.
type prefaceConn struct {
	net.Conn
	fp  fingerprint.H2Fingerprint
	ok  bool
	buf []byte
	off int
}

// newPrefaceConn reads and parses the h2 preface from c, capturing the bytes consumed so they can be
// replayed. Parsing is best-effort: on a malformed/short preface ok is false and the captured bytes are
// still replayed, so the connection is served unharmed (it simply carries no h2 fingerprint).
func newPrefaceConn(c net.Conn) *prefaceConn {
	var captured bytes.Buffer
	fp, err := fingerprint.ParsePreface(io.TeeReader(c, &captured))
	pc := &prefaceConn{Conn: c, buf: captured.Bytes()}
	if err == nil {
		pc.fp = fp
		pc.ok = true
	}
	return pc
}

func (c *prefaceConn) Read(p []byte) (int, error) {
	if c.off < len(c.buf) {
		n := copy(p, c.buf[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(p)
}

// countingConn tees every byte the HTTP/2 server reads into an H2FrameScanner. It returns the bytes
// unchanged, so it only observes the frame stream (HEADERS/RST_STREAM counts) — a scanner bug cannot
// corrupt what the server reads. This is how rapid-reset (CVE-2023-44487) is spotted on a live connection.
type countingConn struct {
	net.Conn
	scanner *fingerprint.H2FrameScanner
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.scanner.Feed(p[:n])
	}
	return n, err
}

// serveH2 is the ALPN "h2" handler: it fingerprints the connection preface, then hands the connection
// (preface replayed) to the x/net HTTP/2 server. Both the TLS ClientHello and the h2 fingerprint are
// threaded through the base context so the per-request prepare() emits the JA3/JA4 and h2 signals.
func (p *ReverseProxy) serveH2(srv *http.Server, tc *tls.Conn, h http.Handler) { // pragma: integration
	ctx := context.Background()
	if pc, ok := tc.NetConn().(*peek.Conn); ok {
		ctx = context.WithValue(ctx, helloKey, pc.ClientHello())
	}
	conn := newPrefaceConn(tc)
	if conn.ok {
		ctx = context.WithValue(ctx, h2Key, &conn.fp)
	}
	// Count frames over the whole connection so a per-request handler can flag a rapid-reset flood.
	scanner := &fingerprint.H2FrameScanner{}
	ctx = context.WithValue(ctx, scannerKey, scanner)
	counting := &countingConn{Conn: conn, scanner: scanner}
	(&http2.Server{}).ServeConn(counting, &http2.ServeConnOpts{Context: ctx, BaseConfig: srv, Handler: h})
}
