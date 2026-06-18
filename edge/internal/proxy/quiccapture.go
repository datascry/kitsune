// edge/proxy/quiccapture — capture client QUIC Initial packets and fingerprint the ClientHello they carry.
// A quic.Listen accept loop drives reads on a tee'd UDP conn; the tee stashes Initials per source for JA4.

package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

	"github.com/quic-go/quic-go"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
)

// quicInitialTee wraps a UDP PacketConn and stashes the QUIC v1 Initial datagrams (long header, type 00)
// seen from each source address, so the ClientHello they carry can be reassembled and fingerprinted.
type quicInitialTee struct {
	net.PacketConn
	mu       sync.Mutex
	initials map[string][][]byte
}

func (t *quicInitialTee) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := t.PacketConn.ReadFrom(p)
	if err == nil && n > 0 && p[0]&0xc0 == 0xc0 && p[0]&0x30 == 0x00 { // long header, fixed bit, Initial
		t.mu.Lock()
		key := addr.String()
		if len(t.initials[key]) < 8 { // a hello fragments across a few Initials; cap to bound memory
			t.initials[key] = append(t.initials[key], append([]byte(nil), p[:n]...))
		}
		t.mu.Unlock()
	}
	return n, addr, err
}

func (t *quicInitialTee) fingerprint(addr string) (*fingerprint.ClientHello, error) {
	t.mu.Lock()
	pkts := t.initials[addr]
	t.mu.Unlock()
	return fingerprint.ParseQUICInitials(pkts)
}

// QUICCapturer serves QUIC on a UDP address purely to elicit and capture client Initials; it accepts (and
// immediately closes) connections so quic-go drives reads on the tee. Fingerprint returns the QUIC
// ClientHello seen from a source address (JA3/JA4 over QUIC), or an error if none was captured.
type QUICCapturer struct {
	tee      *quicInitialTee
	listener *quic.Listener
}

// NewQUICCapturer binds a UDP listener at addr and starts capturing QUIC Initials. cert is the edge's
// TLS certificate; ALPN advertises h3 so real browsers will attempt QUIC here.
func NewQUICCapturer(addr string, cert *tls.Certificate) (*QUICCapturer, error) {
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	tee := &quicInitialTee{PacketConn: udp, initials: map[string][][]byte{}}
	ln, err := quic.Listen(tee, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h3"},
	}, &quic.Config{})
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	c := &QUICCapturer{tee: tee, listener: ln}
	go c.acceptLoop()
	return c, nil
}

func (c *QUICCapturer) acceptLoop() {
	for {
		conn, err := c.listener.Accept(context.Background())
		if err != nil {
			return // listener closed
		}
		_ = conn.CloseWithError(0, "") // we only wanted the handshake; the Initial is already captured
	}
}

// Addr is the UDP address the capturer is listening on.
func (c *QUICCapturer) Addr() net.Addr { return c.tee.LocalAddr() }

// Fingerprint returns the QUIC ClientHello captured from source address addr (e.g. "ip:port"), or error.
func (c *QUICCapturer) Fingerprint(addr string) (*fingerprint.ClientHello, error) {
	return c.tee.fingerprint(addr)
}

// Close stops the listener and releases the UDP socket.
func (c *QUICCapturer) Close() error { return c.listener.Close() }
