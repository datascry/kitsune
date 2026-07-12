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
			{
				Kind:     "timing",
				Prompt:   "Press and hold each target for its shown duration, then release. A motor-timing-precision gate (not a wild-captcha clone): the release-error std across targets convicts superhuman precision — a target-exact or constant-offset bot collapses the std to ~0 while a human has a jitter floor; claiming more total hold time than the solve took is also impossible (timing_superhuman).",
				Endpoint: "GET /arena/timing?level=<level>",
				Params:   []string{"level"},
			},
			{
				Kind:     "keymap",
				Prompt:   "The keyboard is silently remapped — discover the mapping by probing and type the target. A broken-keyboard gate (not a wild-captcha clone): a correct answer with ZERO exploration (no backspaces) means the client decoded the remap from the payload instead of probing it (typed_without_exploration); a solve faster than the discover+type floor also convicts.",
				Endpoint: "GET /arena/keymap?level=<level>",
				Params:   []string{"level"},
			},
			{
				Kind:     "presshold",
				Prompt:   "Press and hold the button for the shown duration, then release. A press-and-hold gate (Cloudflare Press & Hold / DataDome / HUMAN family): the held-pointer tremor convicts a scripted hold — a real hand drifts continuously while an injected hold pins its samples to one coordinate (variance ~ 0), and claiming a longer hold than the whole solve window is impossible (hold_robotic).",
				Endpoint: "GET /arena/presshold?level=<level>",
				Params:   []string{"level"},
			},
			{
				Kind:     "sequence",
				Prompt:   "Click the numbered tiles in order (GeeTest icon-order / NetEase Yidun family): solving faster than a human can visually locate + click N ordered targets (age < N * a per-target floor), or a metronomic inter-click cadence (a fixed-delay clicker, std ~ 0), convicts on coherence (seqclick_superhuman).",
				Endpoint: "GET /arena/sequence?level=<level>",
				Params:   []string{"level"},
			},
			{
				Kind:     "locate",
				Prompt:   "Click the center of the named target among distractors on a free canvas (hCaptcha 'click the center of X' / AWS WAF family): a CV solver computes the centroid and clicks it pixel-perfect (distance ~ 0, below human aim variance), or solves faster than a human can locate+aim — either convicts on coherence (localize_superhuman).",
				Endpoint: "GET /arena/locate?level=<level>",
				Params:   []string{"level"},
			},
			{
				Kind:     "match",
				Prompt:   "Click the arrow that points the same way as the reference (Arkose 'faces the same way' / hCaptcha 'which go together' family): a relational task — compare the reference against each candidate. Solving faster than a human can scan a reference + N candidates convicts on coherence (match_superhuman).",
				Endpoint: "GET /arena/match?level=<level>",
				Params:   []string{"level"},
			},
			{
				Kind:     "slide",
				Prompt:   "Slide the 8-puzzle (3x3) into order (KeyCAPTCHA / 15-puzzle family): an OPTIMAL plan — the exact BFS-minimum move count on a non-trivial scramble, which a human wandering never hits — or solving faster than a human can slide the tiles convicts on coherence (slide_superhuman).",
				Endpoint: "GET /arena/slide?level=<level>",
				Params:   []string{"level"},
			},
			{
				Kind:     "pattern",
				Prompt:   "Draw one line through the dots in order (connect-the-dots / Android-pattern-lock family): a synthetic stroke that hugs the ideal polyline too closely (mean deviation below the human hand-tremor floor), or a draw faster than a human can move through N waypoints, convicts on coherence (pattern_superhuman).",
				Endpoint: "GET /arena/pattern?level=<level>",
				Params:   []string{"level"},
			},
			{
				Kind:     "reaction",
				Prompt:   "Click as soon as the box turns green (a 'click when ready' reaction check): a reaction latency below the human physiological floor (~150ms), or negative — a click reaching the server before the go (anticipation) — convicts on coherence (reaction_superhuman). Server-observed, unforgeable in the too-fast direction.",
				Endpoint: "GET /arena/reaction?level=<level>",
				Params:   []string{"level"},
			},
			{
				Kind:     "spotdiff",
				Prompt:   "Two near-identical panels differ in K spots — click each difference (a prevalent wild style): a bot pixel-diffs the panels and clicks the exact centroid of each change (pixel-perfect) and finds all K instantly, while a human eyeballs and needs seconds per difference — either convicts on coherence (spotdiff_superhuman).",
				Endpoint: "GET /arena/spotdiff?level=<level>",
				Params:   []string{"level"},
			},
			{
				Kind:     "pursuit",
				Prompt:   "Keep the cursor on the moving dot for a few seconds (smooth-pursuit tracking): human pursuit trails a moving target with tens of px of error (visuomotor lag + jitter), while a bot that computes the deterministic path holds the cursor within a few px — superhuman tracking accuracy convicts on coherence (pursuit_superhuman).",
				Endpoint: "GET /arena/pursuit?level=<level>",
				Params:   []string{"level"},
			},
			{
				Kind:     "count",
				Prompt:   "How many circles of the named colour are there? (a counting captcha). A bot CV-counts the shapes instantly while a human scans each one — a correct answer faster than a human can scan the whole scene (age < totalShapes * a per-shape floor) convicts on coherence (count_superhuman). Reuses the solve-speed tell.",
				Endpoint: "GET /arena/count?level=<level>",
				Params:   []string{"level"},
			},
		},
	}
}
