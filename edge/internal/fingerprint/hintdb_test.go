// edge/fingerprint/hintdb_test — tests for loading the JA4 hint table.
// Covers the embedded seed, a file override, and malformed inputs.

package fingerprint

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultHints(t *testing.T) {
	table := DefaultHints()
	h, ok := table.Lookup("t13d1516h2_8daaf6152771_example_chrome")
	if !ok || h.Browser != "chrome" || h.OS != "windows" {
		t.Errorf("seed lookup: %+v ok=%v", h, ok)
	}
}

func TestLoadHintsFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.json")
	if err := os.WriteFile(path, []byte(`{"abc":{"browser":"safari","os":"macOS"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	table, err := LoadHints(path)
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := table.Lookup("abc"); h.Browser != "safari" {
		t.Errorf("loaded hint: %+v", h)
	}
}

func TestLoadHintsErrors(t *testing.T) {
	if _, err := LoadHints("/no/such/file.json"); err == nil {
		t.Error("expected error for missing file")
	}
	if _, err := parseHints([]byte("not json")); err == nil {
		t.Error("expected error for malformed json")
	}
}
