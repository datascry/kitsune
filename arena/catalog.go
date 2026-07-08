// arena/catalog — the machine-readable manifest of the CAPTCHA challenge space (GET /arena/catalog).
// A red-teamer reads it to iterate every variant (kind x level x font/category) when benchmarking OCR / image models.

package arena

// catalogChallenge describes one challenge kind and the axes a red-teamer can vary on it when benchmarking a solver.
type catalogChallenge struct {
	Kind       string   `json:"kind"`
	Prompt     string   `json:"prompt"`
	Endpoint   string   `json:"endpoint,omitempty"`   // the route to fetch it, if not the default GET /arena/captcha?kind=
	Params     []string `json:"params,omitempty"`     // query params the caller can set (e.g. ["font"] on text)
	Fonts      []string `json:"fonts,omitempty"`      // text: the ?font=<name> typeface pool (the OCR bench axis)
	Charsets   []string `json:"charsets,omitempty"`   // text: the ?charset=<name> character-set options (the OCR bench axis)
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
		Note: "Owned, allowlist-scoped challenge bench. The image/OCR kinds (text/math/image-*/honeypot) are an OCR / " +
			"image-classification benchmark corpus — iterate kind x level (x font/category); fetch at GET " +
			"/arena/captcha?kind=<kind>&level=<level>[&font=<font>]. The 'track' kind is a distinct REAL-TIME " +
			"visual-tracking gate (its own endpoint) that catches LLM browser agents by the physics of their " +
			"snapshot->reason->act loop, not OCR. Every asset is license-clean; every challenge is human-solvable.",
		Levels: []string{"easy", "medium", "hard"},
		Challenges: []catalogChallenge{
			{
				Kind: "text", Prompt: "Type the characters in the image.",
				Params: []string{"font", "charset"}, Fonts: captchaFontNames, Charsets: captchaCharsetNames,
				Charset: captchaAlphabet + " (+ the 0O/1IL confusables at hard)",
			},
			{Kind: "math", Prompt: "Arithmetic — addition (easy), mixed ops (medium), multiplication (hard)."},
			{Kind: "clock", Prompt: "Read the analog clock and type the time it shows (H:MM). A rendered clock face at a random time — owned procedural, a visual-reasoning task beyond glyph OCR; minutes are a multiple of 5."},
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
			{
				Kind:     "track",
				Prompt:   "Click the moving dot. A real-time visual-tracking gate: a human servos to the current dot; a snapshot-then-reason LLM agent clicks the seconds-old position it last saw and is convicted (bh.arena_stale_snapshot). Level sets dot speed.",
				Endpoint: "GET /arena/track/play?level=<level>",
				Params:   []string{"level"},
			},
			{
				Kind:     "audio",
				Prompt:   "Type the spoken digits you hear. A spoken-digit WAV synthesised in pure Go from an embedded CC-BY-SA FSDD corpus, distorted (noise/tone/overlap) per level — the ASR-benchmark twin of the text/OCR gate. A correct answer faster than the clip's real-time playback is ASR automation (server-observed).",
				Endpoint: "GET /arena/audio?level=<level>",
				Params:   []string{"level"},
			},
			{
				Kind:     "spatial",
				Prompt:   "Select every cube with the target colour on top. An isometric-cube grid at random 3D orientations — the Arkose/FunCaptcha 3D-object family; identify the TOP face of a rotated cube (spatial reasoning), not a 2D glyph. Owned procedural, zero-license.",
				Endpoint: "GET /arena/spatial?level=<level>",
				Params:   []string{"level"},
			},
			{
				Kind:     "shell",
				Prompt:   "Watch the shuffle, then click the cup hiding the ball. A track-under-occlusion gate: the ball is hidden during a server-defined swap sequence, so a snapshot-then-reason agent cannot follow it. A correct answer faster than the shuffle runtime was precomputed from the swap payload (solved_before_shuffle).",
				Endpoint: "GET /arena/shell?level=<level>",
				Params:   []string{"level"},
			},
		},
	}
}
