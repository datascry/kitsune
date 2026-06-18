// edge/proxy/reverseproxy — transparent TLS-terminating reverse proxy with fingerprint capture.
// Peeks the ClientHello, mints/keeps ks_sid, forwards network signals, proxies HTTP to a backend.

package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
	"github.com/datascry/kitsune/edge/internal/peek"
	"github.com/datascry/kitsune/edge/internal/session"
	"github.com/datascry/kitsune/edge/internal/signal"
)

type ctxKey int

const helloKey ctxKey = 0

// prepared is the per-request fingerprint decoration the proxy applies.
type prepared struct {
	sessionID string
	signals   []signal.Signal
	setCookie *http.Cookie // non-nil when a new session id was minted
}

// prepare derives the session id (from the ks_sid cookie or freshly minted) and the network signals
// for a request whose connection produced the given ClientHello. Pure + testable.
func prepare(
	r *http.Request,
	hello *fingerprint.ClientHello,
	hints fingerprint.HintTable,
	newID IDFunc,
	now time.Time,
) (prepared, error) {
	var out prepared
	if c, err := r.Cookie(session.CookieName); err == nil {
		out.sessionID = c.Value
	} else {
		id, err := newID()
		if err != nil {
			return out, err
		}
		out.sessionID = id
		// Not HttpOnly: the in-page collector reads ks_sid to tag its telemetry with the session.
		out.setCookie = &http.Cookie{Name: session.CookieName, Value: id, Path: "/"}
	}
	if hello != nil {
		out.signals = signal.FromClientHello(out.sessionID, hello, hints, now)
	}
	return out, nil
}

// ReverseProxy is a transparent TLS edge in front of a backend app.
type ReverseProxy struct {
	backend     *httputil.ReverseProxy
	detectorURL string
	hints       fingerprint.HintTable
	newID       IDFunc
	now         func() time.Time
	client      *http.Client
}

// NewReverseProxy builds a reverse proxy forwarding to backendURL and reporting to detectorURL.
func NewReverseProxy(backendURL, detectorURL string, hints fingerprint.HintTable) (*ReverseProxy, error) {
	target, err := url.Parse(backendURL)
	if err != nil {
		return nil, err
	}
	return &ReverseProxy{
		backend:     httputil.NewSingleHostReverseProxy(target),
		detectorURL: detectorURL,
		hints:       hints,
		newID:       session.NewID,
		now:         time.Now,
		client:      &http.Client{Timeout: 5 * time.Second},
	}, nil
}

func (p *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hello, _ := r.Context().Value(helloKey).(*fingerprint.ClientHello)
	prep, err := prepare(r, hello, p.hints, p.newID, p.now())
	if err != nil {
		http.Error(w, "could not mint session id", http.StatusInternalServerError)
		return
	}
	if prep.setCookie != nil {
		http.SetCookie(w, prep.setCookie)
		r.AddCookie(prep.setCookie)
	}
	r.Header.Set("X-KS-Session", prep.sessionID)
	p.forward(prep.signals)
	p.backend.ServeHTTP(w, r)
}

func (p *ReverseProxy) forward(sigs []signal.Signal) {
	if p.detectorURL == "" || len(sigs) == 0 {
		return
	}
	body, err := signal.Marshal(sigs)
	if err != nil {
		return
	}
	resp, err := p.client.Post(p.detectorURL+"/ingest", "application/json", bytes.NewReader(body))
	if err == nil {
		_ = resp.Body.Close()
	}
}

// ListenAndServe runs the proxy on addr with TLS terminated using an ephemeral self-signed cert.
func (p *ReverseProxy) ListenAndServe(addr string) error { // pragma: integration
	cert, err := selfSignedCert()
	if err != nil {
		return err
	}
	inner, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12}
	ln := tls.NewListener(peek.NewListener(inner), cfg)

	srv := &http.Server{
		Handler:     p,
		ReadTimeout: 15 * time.Second,
		// Disable HTTP/2 so the ClientHello captured per-connection in ConnContext propagates to
		// request contexts (the bundled h2 server does not carry ConnContext values to streams).
		// HTTP/2 fingerprinting is a separate, deferred signal; HTTP/1.1 is fine for the edge.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc, ok := c.(*tls.Conn); ok {
				if pc, ok := tc.NetConn().(*peek.Conn); ok {
					return context.WithValue(ctx, helloKey, pc.ClientHello())
				}
			}
			return ctx
		},
	}
	return srv.Serve(ln)
}

func selfSignedCert() (*tls.Certificate, error) { // pragma: integration
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kitsune-edge"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
