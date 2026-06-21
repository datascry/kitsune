// edge/proxy/h2serve_test — assert the h2 preface is fingerprinted and replayed byte-for-byte.
// A short read leaves ok=false but still replays the captured bytes so serving is unharmed.

package proxy

import (
	"bytes"
	"io"
	"net"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
)

// rapidResetStream builds a client preface followed by n HEADERS+RST_STREAM pairs — a rapid-reset flood.
func rapidResetStream(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&buf, nil)
	for i := 0; i < n; i++ {
		sid := uint32(2*i + 1)
		if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: sid, BlockFragment: []byte{0x88}, EndHeaders: true}); err != nil {
			t.Fatal(err)
		}
		if err := fr.WriteRSTStream(sid, http2.ErrCodeCancel); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestCountingConnFeedsScanner(t *testing.T) {
	raw := rapidResetStream(t, 120)
	s := &fingerprint.H2FrameScanner{}
	cc := &countingConn{Conn: fakeConn{r: bytes.NewReader(raw)}, scanner: s}
	got, err := io.ReadAll(cc)
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Error("countingConn must pass bytes through unchanged")
	}
	if !s.RapidReset() {
		t.Errorf("scanner should flag rapid-reset: headers=%d rst=%d", s.Headers.Load(), s.RSTStreams.Load())
	}
}

// fakeConn is a net.Conn whose Read is backed by an in-memory reader; other methods are unused here.
type fakeConn struct {
	net.Conn
	r io.Reader
}

func (f fakeConn) Read(p []byte) (int, error) { return f.r.Read(p) }

// chromePreface builds a Chrome-shaped client preface followed by trailingTag, so a test can confirm
// the replayed stream contains both the consumed preface and any bytes that came after it.
func chromePreface(t *testing.T, trailingTag []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&buf, nil)
	if err := fr.WriteSettings(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6291456},
	); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteWindowUpdate(0, 15663105); err != nil {
		t.Fatal(err)
	}
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, hf := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"}, {Name: ":authority", Value: "edge"},
		{Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"},
	} {
		_ = enc.WriteField(hf)
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: hb.Bytes(), EndHeaders: true, EndStream: true,
	}); err != nil {
		t.Fatal(err)
	}
	return append(buf.Bytes(), trailingTag...)
}

func TestNewPrefaceConnFingerprintsAndReplays(t *testing.T) {
	trailing := []byte("AFTER-PREFACE")
	raw := chromePreface(t, trailing)
	pc := newPrefaceConn(fakeConn{r: bytes.NewReader(raw)})

	if !pc.ok {
		t.Fatal("expected ok=true on a well-formed preface")
	}
	if pc.fp.Browser() != "chrome" {
		t.Errorf("browser=%s want chrome", pc.fp.Browser())
	}
	// Reading the wrapped conn must reproduce the original stream exactly: replayed preface + the rest.
	got, err := io.ReadAll(pc)
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("replayed stream differs from original (len got=%d want=%d)", len(got), len(raw))
	}
	if !bytes.HasSuffix(got, trailing) {
		t.Error("replayed stream lost the post-preface bytes")
	}
}

func TestNewPrefaceConnBadPrefaceStillReplays(t *testing.T) {
	raw := []byte("not a valid http2 preface at all, just bytes")
	pc := newPrefaceConn(fakeConn{r: bytes.NewReader(raw)})
	if pc.ok {
		t.Fatal("expected ok=false on a malformed preface")
	}
	// Even on a parse failure the consumed bytes are buffered and replayed, so serving is unharmed.
	got, _ := io.ReadAll(pc)
	if !bytes.Equal(got, raw) {
		t.Errorf("malformed preface not replayed intact: got %q", got)
	}
}
