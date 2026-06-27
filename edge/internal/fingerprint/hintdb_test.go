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

func TestRealSafariFirefoxJA4Hints(t *testing.T) {
	// Real-browser JA4s grounded against the FoxIO ja4plus-mapping (NOT the Playwright-build captures): real
	// Safari t13d2014h2_a09f3c656075 (20 ciphers, vs Playwright-WebKit's 723694b0fccc) and real Firefox
	// t13d1715h2_5b57614c22b0 (15 extensions, vs the Playwright-Firefox capture's 17). Classify via the
	// JA4_c-independent a+b prefix, so a real Safari/Firefox visitor's TLS is recognised (no FP — its UA
	// matches), and a Chromium faking that engine's TLS under a mismatched UA is convicted.
	table := DefaultHints()
	if h, ok := table.Lookup("t13d2014h2_a09f3c656075_14788d8d241b"); !ok || h.Browser != "safari" {
		t.Errorf("real Safari JA4 should classify safari: %+v ok=%v", h, ok)
	}
	if h, ok := table.Lookup("t13d1715h2_5b57614c22b0_7121afd63204"); !ok || h.Browser != "firefox" {
		t.Errorf("real Firefox JA4 should classify firefox: %+v ok=%v", h, ok)
	}
	// Chrome ships in two real extension-count variants (16 and 17), both per the FoxIO mapping; cover both.
	if h, ok := table.Lookup("t13d1517h2_8daaf6152771_b0da82dd1658"); !ok || h.Browser != "chrome" {
		t.Errorf("real Chrome 17-ext JA4 should classify chrome: %+v ok=%v", h, ok)
	}
}

func TestToolJA4ClientHints(t *testing.T) {
	// Live-captured non-browser HTTP-client JA4s (through the edge): a Client hint, no Browser. The prefix
	// fallback classifies them JA4_c-independently, so they catch the tool regardless of the trailing hash.
	table := DefaultHints()
	for _, tc := range []struct {
		ja4, client string
	}{
		{"t13d3012h2_1d37bd780c83_882d495ac381", "curl"},
		{"t13d131100_f57a46bbacb6_ab7e3b40a677", "go-http"},
		{"t13d171100_ab0a1bf427ad_8e6e362c5eac", "python-urllib"},
	} {
		h, ok := table.Lookup(tc.ja4)
		if !ok || h.Client != tc.client || h.Browser != "" {
			t.Errorf("%s: got %+v ok=%v, want client=%q browser=\"\"", tc.ja4, h, ok, tc.client)
		}
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
