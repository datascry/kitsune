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
	// Real captured go-tls (forged Chrome) JA4.
	h, ok := table.Lookup("t13d1516h2_8daaf6152771_02713d6af862")
	if !ok || h.Browser != "chrome" || h.OS != "windows" {
		t.Errorf("seed lookup: %+v ok=%v", h, ok)
	}
}

func TestPrefixFallbackClassifiesFirefox(t *testing.T) {
	table := DefaultHints()
	// The live-captured Camoufox JA4 (its JA4_c randomises per launch) classifies via the a+b prefix.
	if h, ok := table.Lookup("t13d1717h2_5b57614c22b0_3cbfd9057e0d"); !ok || h.Browser != "firefox" {
		t.Errorf("camoufox JA4 should classify firefox via prefix: %+v ok=%v", h, ok)
	}
	// A different JA4_c on the same cipher prefix resolves the same way (the point of prefix matching).
	if h, ok := table.Lookup("t13d1717h2_5b57614c22b0_ffffffffffff"); !ok || h.Browser != "firefox" {
		t.Errorf("prefix fallback should be JA4_c-independent: %+v ok=%v", h, ok)
	}
}

func TestLookupRejectsNonMatches(t *testing.T) {
	table := DefaultHints()
	if _, ok := table.Lookup("t13d9999h2_deadbeefcafe_0123456789ab"); ok {
		t.Error("an unrelated JA4 must not match")
	}
	if _, ok := table.Lookup("nounderscores"); ok {
		t.Error("a malformed JA4 (no underscores) must not match")
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
