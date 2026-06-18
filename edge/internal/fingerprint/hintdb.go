// edge/fingerprint/hintdb — load the JA4 -> browser/OS hint table from JSON (embedded or a file).
// The mechanism for populating hints; ship a real JA4 fingerprint DB via KITSUNE_JA4_HINTS.

package fingerprint

import (
	_ "embed"
	"encoding/json"
	"os"
)

// embeddedHints is a small seed of EXAMPLE entries (not real fingerprints) showing the file format.
//
//go:embed ja4_hints.json
var embeddedHints []byte

func parseHints(data []byte) (HintTable, error) {
	var m map[string]Hint
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return HintTable(m), nil
}

// DefaultHints returns the embedded seed table. Replace with a real JA4 database in production.
func DefaultHints() HintTable {
	t, err := parseHints(embeddedHints)
	if err != nil {
		return HintTable{}
	}
	return t
}

// LoadHints reads a JA4 hint table from a JSON file (overrides the embedded seed).
func LoadHints(path string) (HintTable, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseHints(data)
}
