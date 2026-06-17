// edge/fingerprint/hints — map a raw JA4 to coarse browser/OS hints.
// A pluggable lookup table (empty by default); production loads a JA4 fingerprint database.

package fingerprint

// Hint is a coarse browser/OS label derived from a fingerprint.
type Hint struct {
	Browser string
	OS      string
}

// Unknown is returned when a fingerprint is not in the table.
var Unknown = Hint{Browser: "unknown", OS: "unknown"}

// HintTable maps a full JA4 string to a Hint. Swap in a real DB (FoxIO JA4 db) behind this type.
type HintTable map[string]Hint

// Lookup returns the hint for a JA4, and whether it was found.
func (t HintTable) Lookup(ja4 string) (Hint, bool) {
	h, ok := t[ja4]
	if !ok {
		return Unknown, false
	}
	return h, true
}
