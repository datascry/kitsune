// arena/catalog — the machine-readable manifest of the CAPTCHA challenge space (GET /arena/catalog).
// A red-teamer reads it to iterate every variant (kind x level x font/category) when benchmarking OCR / image models.

package arena

// catalogChallenge describes one CAPTCHA kind and the axes a red-teamer can vary on it when benchmarking a solver.
type catalogChallenge struct {
	Kind       string   `json:"kind"`
	Prompt     string   `json:"prompt"`
	Params     []string `json:"params,omitempty"`     // query params the caller can set (e.g. ["font"] on text)
	Fonts      []string `json:"fonts,omitempty"`      // text: the ?font=<name> typeface pool (the OCR bench axis)
	Categories []string `json:"categories,omitempty"` // image gates: the category domains (randomized per challenge)
	Charset    string   `json:"charset,omitempty"`    // text: the glyph set the answer is drawn from
}

// Catalog is the full enumeration returned by GET /arena/catalog.
type Catalog struct {
	Note       string             `json:"note"`
	Levels     []string           `json:"levels"`
	Challenges []catalogChallenge `json:"challenges"`
}

// arenaCatalog assembles the manifest from the LIVE sources (the font pool, the image category lists) so it never
// drifts from what the gates actually serve — add a font or a category and it appears here automatically.
func arenaCatalog() Catalog {
	return Catalog{
		Note: "Owned, allowlist-scoped CAPTCHA bench. Iterate kind x level (x font/category) to benchmark OCR / " +
			"image-classification models against a rich corpus. Every asset is license-clean; every challenge is " +
			"human-solvable. Fetch a challenge at GET /arena/captcha?kind=<kind>&level=<level>[&font=<font>].",
		Levels: []string{"easy", "medium", "hard"},
		Challenges: []catalogChallenge{
			{
				Kind: "text", Prompt: "Type the characters in the image.",
				Params: []string{"font"}, Fonts: captchaFontNames,
				Charset: captchaAlphabet + " (+ the 0O/1IL confusables at hard)",
			},
			{Kind: "math", Prompt: "Arithmetic — addition (easy), mixed ops (medium), multiplication (hard)."},
			{
				Kind: "image-select", Prompt: "Select every <category> — emoji glyph grid (Noto Emoji, OFL 1.1).",
				Categories: emojiCatOrder,
			},
			{
				Kind: "image-doodle", Prompt: "Select every <category> — Quick, Draw! sketch grid (CC BY 4.0).",
				Categories: doodleGroupOrder,
			},
			{
				Kind: "image-shapes", Prompt: "Select every <shape> — owned procedural geometric-shape grid (zero-license).",
				Categories: shapeOrder,
			},
			{Kind: "honeypot", Prompt: "Submit without filling the hidden field (no difficulty axis)."},
		},
	}
}
