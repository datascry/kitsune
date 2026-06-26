// evaders/arena-solver/parse — pure parsing the browserless solver uses to beat the arena's CAPTCHA gates.
// SVG-text extraction, SVG-tile shape classification, math-prompt arithmetic — the findings these prove.

// These functions are the heart of the red-side finding: the arena's vector (SVG) captchas carry their answer
// in the MARKUP, so a browserless client reads it without OCR — a distorted-text image and an unlabelled tile
// grid are only as strong as the image format, and a vector format leaks. (Kept network-free so it unit-tests.)

package main

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	reText = regexp.MustCompile(`(?s)<text[^>]*>([^<]+)</text>`)
	reMath = regexp.MustCompile(`What is (\d+) \+ (\d+)`)
)

// decodeDataSVG strips the `data:image/svg+xml;utf8,` prefix and undoes the %23→# encoding the gate applies,
// yielding the raw SVG markup.
func decodeDataSVG(dataURI string) string {
	i := strings.Index(dataURI, ",")
	if i < 0 {
		return ""
	}
	body := dataURI[i+1:]
	if dec, err := url.QueryUnescape(body); err == nil {
		return dec
	}
	return strings.ReplaceAll(body, "%23", "#")
}

// extractSVGText reads the characters out of a distorted-text SVG in document order — the gate emits one
// <text> element per character left-to-right, so the concatenation IS the code (no OCR needed: the answer is
// in the markup). This is the finding for the `text` gate.
func extractSVGText(dataURI string) string {
	svg := decodeDataSVG(dataURI)
	var b strings.Builder
	for _, m := range reText.FindAllStringSubmatch(svg, -1) {
		b.WriteString(strings.TrimSpace(m[1]))
	}
	return b.String()
}

// solveMath parses "What is A + B?" and returns the sum as a string (the trivial `math` solve).
func solveMath(prompt string) string {
	m := reMath.FindStringSubmatch(prompt)
	if m == nil {
		return ""
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	return strconv.Itoa(a + b)
}

// targetShape pulls the target shape out of an image-select prompt ("Select every triangle.").
func targetShape(prompt string) string {
	p := strings.ToLower(prompt)
	for _, s := range []string{"circle", "square", "triangle", "star"} {
		if strings.Contains(p, s) {
			return s
		}
	}
	return ""
}
