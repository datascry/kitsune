// edge/proxy/h1serve_test — the slowConn tee, the single-connection listener, and serveH1 end to end.
// Integration cases drive a real TLS http/1.1 connection so a normal request serves and a slowloris emits.

package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
	"github.com/datascry/kitsune/edge/internal/signal"
)

// stubConn is a self-contained net.Conn for the unit tests: it reads from r, no-ops Write/Close/deadlines,
// and reports addr. (The shared fakeConn embeds a nil net.Conn, so its Close would panic.)
type stubConn struct {
	r    io.Reader
	addr net.Addr
}

func (c stubConn) Read(p []byte) (int, error) {
	if c.r == nil {
		return 0, io.EOF
	}
	return c.r.Read(p)
}
func (c stubConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c stubConn) Close() error                     { return nil }
func (c stubConn) LocalAddr() net.Addr              { return c.addr }
func (c stubConn) RemoteAddr() net.Addr             { return c.addr }
func (c stubConn) SetDeadline(time.Time) error      { return nil }
func (c stubConn) SetReadDeadline(time.Time) error  { return nil }
func (c stubConn) SetWriteDeadline(time.Time) error { return nil }

func TestSlowConnFeedsScanner(t *testing.T) {
	base := time.Unix(1000, 0)
	clock := base
	// Dribble a partial header (no terminating CRLFCRLF) through the tee.
	raw := []byte("GET / HTTP/1.1\r\nHost: edge\r\nX-Pad: aaaa\r\n")
	s := &fingerprint.SlowLorisScanner{}
	sc := newSlowConn(stubConn{r: bytes.NewReader(raw)}, s, func() time.Time { return clock })
	got, err := io.ReadAll(sc)
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Error("slowConn must pass bytes through unchanged")
	}
	if s.HeaderComplete() {
		t.Fatal("a partial header (no CRLFCRLF) must be incomplete")
	}
	if !s.SlowRequest(base.Add(12*time.Second), slowHTTPMinAge, slowHTTPMaxBytes) {
		t.Error("an incomplete header held past the budget is the slowloris signature")
	}
}

func TestSingleConnListenerHandsOnceThenBlocksUntilClose(t *testing.T) {
	sc := newSlowConn(stubConn{}, &fingerprint.SlowLorisScanner{}, time.Now)
	l := &singleConnListener{conn: sc}
	c, err := l.Accept()
	if err != nil || c != sc {
		t.Fatalf("first Accept must hand out the connection: c=%v err=%v", c, err)
	}
	// The second Accept must block until the connection is closed, then report done.
	returned := make(chan error, 1)
	go func() { _, e := l.Accept(); returned <- e }()
	select {
	case <-returned:
		t.Fatal("second Accept returned before the connection was closed")
	case <-time.After(50 * time.Millisecond):
	}
	_ = sc.Close()
	select {
	case e := <-returned:
		if e != errListenerDone {
			t.Errorf("want errListenerDone after close, got %v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("second Accept did not unblock after Close")
	}
}

// h1Fixture is a full mini edge: a backend, a detector capturing ingested signals, and a proxy with an
// injectable clock — enough to drive serveH1 over a real TLS http/1.1 connection.
type h1Fixture struct {
	proxy    *ReverseProxy
	backend  *httptest.Server
	detector *httptest.Server
	mu       sync.Mutex
	ingested []signal.Signal
	clock    time.Time
}

func newH1Fixture(t *testing.T) *h1Fixture {
	t.Helper()
	f := &h1Fixture{clock: time.Unix(2000, 0)}
	f.backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot) // a distinctive status proving the request reached the backend
	}))
	t.Cleanup(f.backend.Close)
	f.detector = httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var sigs []signal.Signal
		if json.Unmarshal(body, &sigs) == nil {
			f.mu.Lock()
			f.ingested = append(f.ingested, sigs...)
			f.mu.Unlock()
		}
	}))
	t.Cleanup(f.detector.Close)
	p, err := NewReverseProxy(f.backend.URL, f.detector.URL, fingerprint.HintTable{})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	p.now = func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.clock }
	f.proxy = p
	return f
}

func (f *h1Fixture) setClock(tm time.Time) { f.mu.Lock(); f.clock = tm; f.mu.Unlock() }

func (f *h1Fixture) sawKind(kind string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.ingested {
		if s.Kind == kind {
			return true
		}
	}
	return false
}

// tlsH1Pipe returns a handshaken client/server *tls.Conn pair negotiating ALPN http/1.1 over an in-memory pipe.
func tlsH1Pipe(t *testing.T) (client, server *tls.Conn) {
	t.Helper()
	cert, err := selfSignedCert()
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	c1, c2 := net.Pipe()
	server = tls.Server(c2, &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"http/1.1"}})
	client = tls.Client(c1, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}, ServerName: "edge"}) //nolint:gosec
	done := make(chan error, 1)
	go func() { done <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	return client, server
}

func TestServeH1ServesNormalRequest(t *testing.T) {
	f := newH1Fixture(t)
	client, server := tlsH1Pipe(t)
	srv := &http.Server{ReadTimeout: 0} // no deadline; the client closes to end serving
	go f.proxy.serveH1(srv, server, f.proxy)

	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: edge\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("status=%d want %d (request must reach the backend through serveH1)", resp.StatusCode, http.StatusTeapot)
	}
	_ = client.Close()
	if f.sawKind("slow_http_attack") {
		t.Error("a completed request must never emit slow_http_attack")
	}
}

func TestServeH1CatchesSlowloris(t *testing.T) {
	f := newH1Fixture(t)
	base := f.clock
	client, server := tlsH1Pipe(t)
	srv := &http.Server{ReadTimeout: 0}
	done := make(chan struct{})
	go func() { f.proxy.serveH1(srv, server, f.proxy); close(done) }()

	// Dribble a partial header and never send the terminating CRLFCRLF (the slowloris hold).
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: edge\r\nX-Pad: a\r\n")); err != nil {
		t.Fatalf("write partial: %v", err)
	}
	// Let the server read + Feed the partial header at the base clock (client.Write can return before the
	// server's Read tees the bytes, so stamp firstByteAt before advancing the clock).
	time.Sleep(100 * time.Millisecond)
	// The connection has now been held past the age budget; tearing it down must attribute the attack.
	f.setClock(base.Add(12 * time.Second))
	_ = client.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("serveH1 did not return after the slowloris connection closed")
	}
	if !f.sawKind("slow_http_attack") {
		t.Error("a held incomplete-header connection must emit slow_http_attack")
	}
}

func TestConnIP(t *testing.T) {
	// net.Pipe has no host:port, so connIP is exercised here with a real TCP address (the production shape).
	tcp := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 51820}
	if got := connIP(stubConn{addr: tcp}); got != "203.0.113.9" {
		t.Errorf("connIP(tcp) = %q want 203.0.113.9", got)
	}
	if got := connIP(stubConn{addr: nil}); got != "" {
		t.Errorf("connIP(nil addr) = %q want empty", got)
	}
	if got := connIP(nil); got != "" {
		t.Errorf("connIP(nil) = %q want empty", got)
	}
}
