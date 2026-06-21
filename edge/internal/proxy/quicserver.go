// edge/proxy/quicserver — serve HTTP/3 over a tee'd socket; attribute requests to QUIC fingerprint by DCID.
// Per-connection (NAT/migration-stable) successor to the per-IP QUIC bridge — ks_sid-correlated (ADR-0005).

package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
	"github.com/datascry/kitsune/edge/internal/signal"
)

type quicCtxKey int

// quicDCIDKey carries the connection's client DCID (resolved once at connection start) through the request
// context, so the handler attributes by DCID even after the connection migrates to a new source address.
const quicDCIDKey quicCtxKey = iota

// QUICServer serves HTTP/3 over a tee'd UDP socket. The tee records each connection's client Initial (and
// its DCID) as http3 reads datagrams, so an H3 request is attributed to its connection's QUIC fingerprint
// by DCID — per-connection (NAT- and migration-stable), correlated to the ks_sid the request carries. This
// is the per-connection successor to QUICCapturer's per-IP bridge (ADR-0005): the ks_sid arrives ON the
// QUIC connection (in the H3 request cookie), so no source-IP match across the TCP/QUIC boundary is needed.
// The DCID is bound at connection start (ConnContext, where the remote addr still equals the Initial's
// source addr) and read from the request context thereafter, so a later path migration cannot break it.
type QUICServer struct {
	tee     *quicInitialTee
	srv     *http3.Server
	udp     net.PacketConn
	hints   fingerprint.HintTable
	newID   IDFunc
	now     func() time.Time
	forward func([]signal.Signal)
	backend http.Handler
}

// NewQUICServer binds UDP at addr and serves HTTP/3: it mints/reads the ks_sid, emits the request's
// network signals plus the connection's QUIC-fingerprint tells (attributed by DCID), forwards them via
// forward, and proxies the request to backend. cert terminates the QUIC TLS. Call Close to stop.
func NewQUICServer(
	addr string,
	cert *tls.Certificate,
	hints fingerprint.HintTable,
	newID IDFunc,
	now func() time.Time,
	forward func([]signal.Signal),
	backend http.Handler,
) (*QUICServer, error) {
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	tee := &quicInitialTee{PacketConn: udp, initials: map[string]*teeEntry{}}
	qs := &QUICServer{tee: tee, udp: udp, hints: hints, newID: newID, now: now, forward: forward, backend: backend}
	qs.srv = &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"h3"}}, //nolint:gosec
		Handler:   http.HandlerFunc(qs.handle),
		// Bind the per-connection DCID at connection start, where c.RemoteAddr() still equals the Initial's
		// source address the tee keyed on; the handler then attributes by DCID regardless of later migration.
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			if dcid, ok := tee.dcidForAddr(c.RemoteAddr().String()); ok {
				ctx = context.WithValue(ctx, quicDCIDKey, dcid)
			}
			return ctx
		},
	}
	go func() { _ = qs.srv.Serve(tee) }()
	return qs, nil
}

func (qs *QUICServer) handle(w http.ResponseWriter, r *http.Request) {
	// hello/h2fp are TCP-path artifacts (a peeked TLS ClientHello / HTTP/2 preface); over H3 they are absent,
	// and the QUIC fingerprint replaces them. prepare still derives ks_sid + the header-level network signals.
	prep, err := prepare(r, nil, nil, qs.hints, qs.newID, qs.now())
	if err != nil {
		http.Error(w, "could not mint session id", http.StatusInternalServerError)
		return
	}
	if prep.setCookie != nil {
		http.SetCookie(w, prep.setCookie)
		r.AddCookie(prep.setCookie)
	}
	r.Header.Set("X-KS-Session", prep.sessionID)
	if dcid, ok := r.Context().Value(quicDCIDKey).(string); ok && dcid != "" {
		if ch, ferr := qs.tee.fingerprintByDCID(dcid); ferr == nil && ch != nil {
			prep.signals = append(prep.signals, quicTells(prep.sessionID, ch, r.Header.Get("User-Agent"), qs.now())...)
		}
	}
	if qs.forward != nil {
		qs.forward(prep.signals)
	}
	if qs.backend != nil {
		qs.backend.ServeHTTP(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Addr is the UDP address the H3 server is listening on.
func (qs *QUICServer) Addr() net.Addr { return qs.udp.LocalAddr() }

// Close stops serving and releases the UDP socket.
func (qs *QUICServer) Close() error {
	err := qs.srv.Close()
	_ = qs.udp.Close()
	return err
}
