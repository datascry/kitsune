// edge/fingerprint/h2 — compute the Akamai-style HTTP/2 client fingerprint from the connection preface.
// SETTINGS + WINDOW_UPDATE + PRIORITY + pseudo-header order: client-stack choices that resist UA spoofing.

package fingerprint

import (
	"fmt"
	"strings"
)

// H2Setting is one HTTP/2 SETTINGS parameter (id and value), in the order the client sent it. Order and
// values are engine-specific (Chrome sends 1,2,3,4,6; Firefox 1,4,5; Safari 3,4) — a stable fingerprint.
type H2Setting struct {
	ID    uint16
	Value uint32
}

// H2Fingerprint captures the parts of the HTTP/2 connection preface used by the Akamai h2 fingerprint:
// the SETTINGS frame, the initial WINDOW_UPDATE increment, any PRIORITY frames, and the order of the
// request pseudo-headers. These are all client-stack choices below the application layer — a browser
// cannot change them by spoofing its User-Agent, so an h2 fingerprint that disagrees with the UA is a tell.
type H2Fingerprint struct {
	Settings          []H2Setting
	WindowUpdate      uint32
	Priorities        []string // each "streamID:exclusive:dependsOn:weight"
	PseudoHeaderOrder string   // request pseudo-header order, e.g. "m,a,s,p"
}

// String renders the Akamai-format fingerprint: "<settings>|<window_update>|<priority>|<header_order>".
func (f H2Fingerprint) String() string {
	parts := make([]string, 0, len(f.Settings))
	for _, s := range f.Settings {
		parts = append(parts, fmt.Sprintf("%d:%d", s.ID, s.Value))
	}
	priority := "0"
	if len(f.Priorities) > 0 {
		priority = strings.Join(f.Priorities, ",")
	}
	return fmt.Sprintf("%s|%d|%s|%s", strings.Join(parts, ";"), f.WindowUpdate, priority, f.PseudoHeaderOrder)
}

// Browser classifies the client engine from the request pseudo-header order — the most version-stable
// discriminator across HTTP/2 stacks: Chromium sends m,a,s,p; Firefox m,p,a,s; Safari m,s,p,a.
func (f H2Fingerprint) Browser() string {
	switch f.PseudoHeaderOrder {
	case "m,a,s,p":
		return "chrome"
	case "m,p,a,s":
		return "firefox"
	case "m,s,p,a":
		return "safari"
	default:
		return "unknown"
	}
}

// SettingsBrowser classifies the client engine from the *set of SETTINGS identifiers* in the preface —
// a discriminator independent of the pseudo-header order and present even on a connection that has not
// yet sent a request. The version-stable Chromium markers are ENABLE_PUSH(2) and MAX_HEADER_LIST_SIZE(6)
// together with HEADER_TABLE_SIZE(1) and INITIAL_WINDOW_SIZE(4); Firefox alone sends MAX_FRAME_SIZE(5)
// and omits both push and the header-list cap. Note MAX_CONCURRENT_STREAMS(3) is NOT required: headful
// Chrome sends {1,2,3,4,6} but headless Chrome omits 3 (live-captured {1,2,4,6}) — requiring it misses
// real headless Chromium. Classification is deliberately conservative: only Chrome and Firefox have
// stable, distinctive profiles; everything else (Safari varies by version) is "unknown" so it never
// contributes a false contradiction. A SETTINGS engine that disagrees with the pseudo-header-order
// engine is a half-spoofed h2 stack — a tool that patched one facet of the fingerprint but not the other.
func (f H2Fingerprint) SettingsBrowser() string {
	ids := make(map[uint16]bool, len(f.Settings))
	for _, s := range f.Settings {
		ids[s.ID] = true
	}
	switch {
	case ids[1] && ids[2] && ids[4] && ids[6]:
		return "chrome"
	case ids[1] && ids[4] && ids[5] && !ids[2] && !ids[6]:
		return "firefox"
	default:
		return "unknown"
	}
}
