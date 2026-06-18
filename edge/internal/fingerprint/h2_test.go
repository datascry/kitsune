// edge/fingerprint/h2_test — assert the Akamai h2 fingerprint string and the engine classifier.
// Uses documented real-browser SETTINGS / pseudo-header orders (tls.peet.ws, Akamai h2 fingerprinting).

package fingerprint

import "testing"

// A representative Chrome HTTP/2 fingerprint (Chrome ~120; tls.peet.ws).
func chromeH2() H2Fingerprint {
	return H2Fingerprint{
		Settings: []H2Setting{
			{ID: 1, Value: 65536}, {ID: 2, Value: 0}, {ID: 3, Value: 1000},
			{ID: 4, Value: 6291456}, {ID: 6, Value: 262144},
		},
		WindowUpdate:      15663105,
		Priorities:        nil,
		PseudoHeaderOrder: "m,a,s,p",
	}
}

func TestH2StringAkamaiFormat(t *testing.T) {
	got := chromeH2().String()
	want := "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p"
	if got != want {
		t.Errorf("h2 fingerprint\n got=%s\nwant=%s", got, want)
	}
}

func TestH2StringWithPriorities(t *testing.T) {
	// Firefox sends PRIORITY frames; they render comma-joined in the priority field.
	fp := H2Fingerprint{
		Settings:          []H2Setting{{ID: 1, Value: 65536}, {ID: 4, Value: 131072}, {ID: 5, Value: 16384}},
		WindowUpdate:      12517377,
		Priorities:        []string{"3:0:0:201", "5:0:0:101"},
		PseudoHeaderOrder: "m,p,a,s",
	}
	want := "1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101|m,p,a,s"
	if got := fp.String(); got != want {
		t.Errorf("got=%s want=%s", got, want)
	}
}

func TestH2BrowserClassifier(t *testing.T) {
	cases := map[string]string{
		"m,a,s,p": "chrome",
		"m,p,a,s": "firefox",
		"m,s,p,a": "safari",
		"a,m,s,p": "unknown",
		"":        "unknown",
	}
	for order, want := range cases {
		fp := H2Fingerprint{PseudoHeaderOrder: order}
		if got := fp.Browser(); got != want {
			t.Errorf("order %q: got=%s want=%s", order, got, want)
		}
	}
}
