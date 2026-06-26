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

func TestSolveMathAndTarget(t *testing.T) {
	if got := solveMath("What is 7 + 5?"); got != "12" {
		t.Fatalf("solveMath + = %q, want 12", got)
	}
	if got := solveMath("What is 9 - 4?"); got != "5" {
		t.Fatalf("solveMath - = %q, want 5", got)
	}
	if got := solveMath("What is 13 × 14?"); got != "182" {
		t.Fatalf("solveMath × = %q, want 182", got)
	}
	if got := targetShape("Select every triangle."); got != "triangle" {
		t.Fatalf("targetShape = %q, want triangle", got)
	}
}
