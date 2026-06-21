// edge/proxy/quiccapture — capture client QUIC Initial packets and fingerprint the ClientHello they carry.
// A quic.Listen accept loop drives reads on a tee'd UDP conn; the tee stashes Initials per source for JA4.

package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
	"github.com/datascry/kitsune/edge/internal/signal"
)

// quicTeeTTL bounds how long a captured Initial stays attributable. A client's QUIC Initial and the h2
// request it correlates to occur within the same short browsing session (seconds apart); a far longer window
// only invites cross-attribution — a later session reusing the source IP (a recycled NAT/bridge address)
// would otherwise inherit a STALE Initial from an earlier, unrelated client. The TTL also bounds memory: the
// old per-IP map grew without limit (every source IP ever seen retained forever).
const quicTeeTTL = 60 * time.Second

// teeEntry is the captured Initial fragments for one source address plus when they were last seen, so stale
// entries (from a since-departed client whose IP was later recycled) can be expired before mis-attribution.
// dcid is the client-chosen QUIC Destination Connection ID shared by this handshake's Initials — the
// per-CONNECTION key (NAT-stable, migration-stable) that FingerprintByDCID uses for ks_sid correlation
// once the edge serves H3 (ADR-0005); the addr keying remains for the current per-IP bridge.
type teeEntry struct {
	pkts [][]byte
	seen time.Time
	dcid string
}

// quicInitialTee wraps a UDP PacketConn and stashes the QUIC v1 Initial datagrams (long header, type 00)
// seen from each source address, so the ClientHello they carry can be reassembled and fingerprinted. Entries
// expire after quicTeeTTL so a stale Initial from a since-departed client cannot mis-attribute to a later
// session that recycled its source IP.
type quicInitialTee struct {
	net.PacketConn
	mu       sync.Mutex
	initials map[string]*teeEntry
	now      func() time.Time // injectable clock for tests; defaults to time.Now
}

func (t *quicInitialTee) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

func (t *quicInitialTee) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := t.PacketConn.ReadFrom(p)
	if err == nil && n > 0 && p[0]&0xc0 == 0xc0 && p[0]&0x30 == 0x00 { // long header, fixed bit, Initial
		t.mu.Lock()
		key := addr.String()
		e := t.initials[key]
		if e == nil {
			e = &teeEntry{}
			t.initials[key] = e
		}
		if len(e.pkts) < 8 { // a hello fragments across a few Initials; cap to bound memory
			e.pkts = append(e.pkts, append([]byte(nil), p[:n]...))
		}
		if e.dcid == "" { // all Initials of one handshake share the client's DCID; record it once
			if dcid, ok := fingerprint.InitialDCID(p[:n]); ok {
				e.dcid = string(dcid)
			}
		}
		e.seen = t.clock()
		t.mu.Unlock()
	}
	return n, addr, err
}

// take expires every entry older than the TTL (bounding memory + killing stale cross-attribution from a
// recycled source IP) and returns the fragments of the first FRESH entry whose address satisfies pred, or nil.
func (t *quicInitialTee) take(pred func(addr string, e *teeEntry) bool) [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := t.clock().Add(-quicTeeTTL)
	var found [][]byte
	for addr, e := range t.initials {
		if e.seen.Before(cutoff) {
			delete(t.initials, addr) // expired: purge before it can mis-attribute to a recycled IP
			continue
		}
		if found == nil && pred(addr, e) {
			found = e.pkts
		}
	}
	return found
}

func (t *quicInitialTee) fingerprint(addr string) (*fingerprint.ClientHello, error) {
	pkts := t.take(func(a string, _ *teeEntry) bool { return a == addr })
	if pkts == nil {
		return nil, fingerprint.ErrNotQUICInitial
	}
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
	tee := &quicInitialTee{PacketConn: udp, initials: map[string]*teeEntry{}}
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

// FingerprintByIP returns the QUIC ClientHello captured from any port at source IP ip — the request
// arrives over TCP from the same IP on a different port than the client's QUIC socket, so we match on IP.
func (c *QUICCapturer) FingerprintByIP(ip string) (*fingerprint.ClientHello, error) {
	pkts := c.tee.take(func(addr string, _ *teeEntry) bool {
		host, _, err := net.SplitHostPort(addr)
		return err == nil && host == ip
	})
	if pkts == nil {
		return nil, fingerprint.ErrNotQUICInitial
	}
	return fingerprint.ParseQUICInitials(pkts)
}

// FingerprintByDCID returns the QUIC ClientHello captured for the connection whose client Initial carried
// the given Destination Connection ID. Unlike FingerprintByIP this is per-CONNECTION: the DCID is unique to
// one handshake, NAT-stable, and survives path migration, so it does not cross-attribute between clients
// sharing a source IP. It is the attribution primitive for ADR-0005 — once the edge serves H3, the captured
// Initial is linked to the connection (and thus the request's ks_sid) by DCID rather than source address.
func (c *QUICCapturer) FingerprintByDCID(dcid []byte) (*fingerprint.ClientHello, error) {
	want := string(dcid)
	pkts := c.tee.take(func(_ string, e *teeEntry) bool { return e.dcid != "" && e.dcid == want })
	if pkts == nil {
		return nil, fingerprint.ErrNotQUICInitial
	}
	return fingerprint.ParseQUICInitials(pkts)
}

// quicTells builds the QUIC-layer signals for a captured QUIC ClientHello under the given UA: an
// observational marker plus, for a GREASEing-engine UA (Chromium/Safari) whose QUIC hello lacks GREASE, the
// quic_no_grease tell — the QUIC analog of net.tls_grease_vs_ua. Firefox is EXCLUDED via uaGreasesHandshake
// (Gecko does not GREASE; emitting it on a Firefox UA false-fired on real Firefox). NB: quic_no_grease feeds
// only the corroborating-only net.quic_grease_vs_ua (experimental) — the QUIC capture is opportunistic and
// IP-attributed, and has fired on real Chromium QUIC + non-QUIC clients, so it must not convict alone.
func quicTells(sessionID string, ch *fingerprint.ClientHello, ua string, now time.Time) []signal.Signal {
	out := []signal.Signal{signal.Network(sessionID, "quic_observed", true, now)}
	if uaGreasesHandshake(ua) && !ch.HasGREASE() {
		out = append(out, signal.Network(sessionID, "quic_no_grease", true, now))
	}
	// QUIC carries a TLS 1.3 ClientHello, so the post-quantum key-share tell applies here too: a UA
	// claiming current Chrome whose QUIC hello omits X25519MLKEM768 is a stale template (the QUIC analog
	// of net.tls_pq_keyshare_vs_ua). Reuses the same gate + check as the TCP path.
	if chromeUAExpectsPQ(ua) && !ch.HasPostQuantumKeyShare() {
		out = append(out, signal.Network(sessionID, "quic_no_pq_keyshare", true, now))
	}
	return out
}

// Close stops the listener and releases the UDP socket.
func (c *QUICCapturer) Close() error { return c.listener.Close() }
