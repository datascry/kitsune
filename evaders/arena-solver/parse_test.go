// evaders/arena-solver/parse_test — the findings, as tests: vector captchas leak their answer to a parser.
// Asserts SVG-text extraction, SVG-tile classification, and math-prompt solving (no network).

package main

import "testing"

func TestExtractSVGTextReadsTheCode(t *testing.T) {
	// A distorted-text SVG carries each character as a <text> element — so the "answer" is in the markup.
	svg := `data:image/svg+xml;utf8,<svg><text x="14" y="26" transform="rotate(5 14 26)">A</text>` +
		`<text x="36" y="24">B</text><text x="58" y="28">7</text><line x1="0" y1="0" x2="9" y2="9"/></svg>`
	if got := extractSVGText(svg); got != "AB7" {
		t.Fatalf("extractSVGText = %q, want AB7", got)
	}
}

func TestClassifyTile(t *testing.T) {
	cases := map[string]string{
		`data:image/svg+xml;utf8,<svg><circle cx="30" cy="30" r="22"/></svg>`:                                              "circle",
		`data:image/svg+xml;utf8,<svg><rect x="12" y="12" width="36" height="36"/></svg>`:                                  "square",
		`data:image/svg+xml;utf8,<svg><polygon points="30,8 52,50 8,50"/></svg>`:                                           "triangle",
		`data:image/svg+xml;utf8,<svg><polygon points="30,6 36,24 55,24 40,36 45,54 30,42 15,54 20,36 5,24 24,24"/></svg>`: "star",
	}
	for svg, want := range cases {
		if got := classifyTile(svg); got != want {
			t.Fatalf("classifyTile = %q, want %q", got, want)
		}
	}
}

func TestSolveMathAndTarget(t *testing.T) {
	if got := solveMath("What is 7 + 5?"); got != "12" {
		t.Fatalf("solveMath = %q, want 12", got)
	}
	if got := targetShape("Select every triangle."); got != "triangle" {
		t.Fatalf("targetShape = %q, want triangle", got)
	}
}
