// edge/peek — capture the raw TLS ClientHello off a live socket, then replay it transparently.
// Wraps a net.Listener so JA3/JA4 are computed from real bytes before the TLS server handshakes.

package peek

import (
	"io"
	"net"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
)

// Conn is a net.Conn that has already consumed the ClientHello record and replays it on Read,
// so a wrapping tls.Server still sees a complete handshake.
type Conn struct {
	net.Conn
	hello *fingerprint.ClientHello
	buf   []byte
	off   int
}

// ClientHello returns the parsed ClientHello, or nil if it could not be parsed.
func (c *Conn) ClientHello() *fingerprint.ClientHello { return c.hello }

func (c *Conn) Read(p []byte) (int, error) {
	if c.off < len(c.buf) {
		n := copy(p, c.buf[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(p)
}

// Listener wraps a net.Listener, capturing+parsing the ClientHello of every accepted connection.
type Listener struct {
	net.Listener
}

// NewListener wraps inner so Accept returns *Conn values carrying the parsed ClientHello.
func NewListener(inner net.Listener) Listener { return Listener{Listener: inner} }

func (l Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Wrap(c), nil
}

// Wrap reads the first TLS record (the ClientHello) from c, parses it, and returns a *Conn that
// replays those bytes. Capture is best-effort: on a short read the bytes are still replayed and
// ClientHello() may be nil, so plain/non-TLS traffic passes through unharmed.
func Wrap(c net.Conn) *Conn {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return &Conn{Conn: c, buf: hdr[:0]}
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	body := make([]byte, recLen)
	n, _ := io.ReadFull(c, body)
	full := append(hdr, body[:n]...)
	hello, _ := fingerprint.ParseClientHello(full)
	return &Conn{Conn: c, hello: hello, buf: full}
}
