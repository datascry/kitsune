// edge/fingerprint/hints — map a raw JA4 to coarse browser/OS hints.
// A pluggable lookup table (empty by default); production loads a JA4 fingerprint database.

package fingerprint

import "strings"

// Hint is a coarse browser/OS label derived from a fingerprint. Client names a NON-browser HTTP client
// (curl / Go net/http / Python urllib …) when the JA4 belongs to a known automation stack rather than a
// browser engine — the two are mutually exclusive (a browser entry sets Browser, a tool entry sets Client),
// so a Client hint over a browser User-Agent is the lazy-scraper tell (default TLS stack + spoofed UA).
type Hint struct {
	Browser string `json:"browser"`
	OS      string `json:"os"`
	Client  string `json:"client"`
}

// Unknown is returned when a fingerprint is not in the table.
var Unknown = Hint{Browser: "unknown", OS: "unknown"}

// HintTable maps a JA4 to a Hint. A key may be a full JA4 (`a_b_c`) or just the JA4_a+JA4_b prefix
// (`a_b`). Swap in a real DB (FoxIO JA4 db) behind this type.
type HintTable map[string]Hint

// Lookup returns the hint for a JA4, and whether it was found. It tries an exact full-JA4 match first,
// then falls back to the JA4_a+JA4_b prefix (dropping JA4_c, the extension hash). JA4_c changes when a
// browser randomises its extension *set* per launch — Camoufox does this — so the cipher-level prefix is
// the stable per-family key; matching it still classifies the TLS engine when the full JA4 drifts.
func (t HintTable) Lookup(ja4 string) (Hint, bool) {
	if h, ok := t[ja4]; ok {
		return h, true
	}
	if prefix, ok := ja4abPrefix(ja4); ok {
		if h, ok := t[prefix]; ok {
			return h, true
		}
	}
	return Unknown, false
}

// ja4abPrefix returns the `JA4_a_JA4_b` prefix (the substring up to the second underscore) of a JA4,
// or false when the string has fewer than two underscores.
func ja4abPrefix(ja4 string) (string, bool) {
	first := strings.IndexByte(ja4, '_')
	if first < 0 {
		return "", false
	}
	rest := strings.IndexByte(ja4[first+1:], '_')
	if rest < 0 {
		return "", false
	}
	return ja4[:first+1+rest], true
}
