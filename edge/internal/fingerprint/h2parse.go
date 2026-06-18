// edge/fingerprint/h2parse — parse the HTTP/2 client connection preface into an H2Fingerprint.
// Reads SETTINGS + WINDOW_UPDATE + PRIORITY frames and the first HEADERS frame's pseudo-header order.

package fingerprint

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// pseudoCode maps an HTTP/2 request pseudo-header to its single-letter Akamai code. The order in which
// the client emits these in the first HEADERS frame is the most version-stable engine discriminator.
var pseudoCode = map[string]string{
	":method":    "m",
	":authority": "a",
	":scheme":    "s",
	":path":      "p",
}

// ParsePreface reads an HTTP/2 client connection preface from r and returns the Akamai-style
// fingerprint. It consumes the 24-byte client magic, then accumulates SETTINGS, the connection-level
// WINDOW_UPDATE, and any PRIORITY frames until the first HEADERS frame, whose decoded pseudo-header
// order completes the fingerprint. These are all client-stack choices a browser cannot change by
// spoofing its User-Agent, so a fingerprint that disagrees with the UA (or JA4) is a tell.
func ParsePreface(r io.Reader) (H2Fingerprint, error) {
	var fp H2Fingerprint
	magic := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(r, magic); err != nil {
		return fp, fmt.Errorf("read h2 preface: %w", err)
	}
	if string(magic) != http2.ClientPreface {
		return fp, fmt.Errorf("not an h2 preface")
	}
	fr := http2.NewFramer(io.Discard, r)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	seenWindow := false
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return fp, fmt.Errorf("read h2 frame: %w", err)
		}
		switch v := f.(type) {
		case *http2.SettingsFrame:
			_ = v.ForeachSetting(func(s http2.Setting) error {
				fp.Settings = append(fp.Settings, H2Setting{ID: uint16(s.ID), Value: s.Val})
				return nil
			})
		case *http2.WindowUpdateFrame:
			// Only the connection-level (stream 0) increment is part of the preface fingerprint.
			if !seenWindow && v.Header().StreamID == 0 {
				fp.WindowUpdate = v.Increment
				seenWindow = true
			}
		case *http2.PriorityFrame:
			ex := 0
			if v.PriorityParam.Exclusive {
				ex = 1
			}
			fp.Priorities = append(fp.Priorities, fmt.Sprintf(
				"%d:%d:%d:%d", v.StreamID, ex, v.PriorityParam.StreamDep, v.PriorityParam.Weight))
		case *http2.MetaHeadersFrame:
			// The first HEADERS frame ends the preface: record pseudo-header order and stop.
			order := make([]string, 0, 4)
			for _, hf := range v.Fields {
				if code, ok := pseudoCode[hf.Name]; ok {
					order = append(order, code)
				}
			}
			fp.PseudoHeaderOrder = strings.Join(order, ",")
			return fp, nil
		}
	}
}
