// arena/gate — the public challenge-gate: serve a PoW challenge and verify a solve, on OWNED infra only.
// Reuses the evaders/pow primitives (anubis/friendlycaptcha/altcha families); never a third-party endpoint.

// The arena is the live-site, self-contained reproduction of documented OPEN web challenge mechanisms. A
// visitor brings any client (browser, script, bot), requests a challenge here, and tries to pass — while
// Kitsune's detector independently scores the same client over the edge. The gate verdict (did you solve the
// PoW?) and the detector verdict (does your client cohere?) are orthogonal and join client-side on ks_sid:
// a no-browser solver can pass the PoW AND still be convicted on the network layer — the demo the lab exists
// to show (a cost gate is not a bot/human discriminator). This package is production (separate from the
// red-team evaders/pow testbed); it imports the pow PRIMITIVES but ships its own HTTP surface.

package arena

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	pow "github.com/datascry/kitsune/evaders/pow"
)

// MaxDifficulty caps the client-requestable difficulty so a hostile query value can't ask the gate to mint
// an absurd puzzle (the per-class defaults below are the norm; this is only the upper bound).
const MaxDifficulty = 26

// minMeasurableHashes/minMeasurableSolve gate solve-rate telemetry to solves with enough work + elapsed to
// measure a rate at all (an easy/near-instant solve is too noisy to report). The rate is SERVER-OBSERVED
// (hashes tried / issue->verify elapsed) — unforgeable, unlike a client-asserted realm proof — but it is NOT a
// standalone conviction: the ABSOLUTE hash rate reflects the CLIENT's hardware (grounded — a slow native solver
// runs ~2 M H/s, below a fast browser's WASM SHA-256), so "too fast" is hardware-dependent. It ships as telemetry
// a hardware-aware detector can later join (solve-rate-vs-claimed-cores); the groundable conviction is the
// OCR/human-time tell (a CAPTCHA solved faster than a human can read+type), which the same issue-time enables.
const (
	minMeasurableHashes = 5e4
	minMeasurableSolve  = 5 * time.Millisecond
)

// minHumanCaptchaSolve is the conservative PHYSIOLOGICAL floor per CAPTCHA kind — no human perceives the
// challenge and submits a CORRECT answer faster than this (reaction + read/decode + type/click). A correct
// solve below the floor is OCR/ML automation, not a human. Set well UNDER real human solve times (which run
// seconds) so a fast, careful, or practised human is NEVER flagged — precision 1.0 is load-bearing; the huge
// human-vs-OCR gap means the exact value is not critical. Honeypot has no entry (its tell is the trap field,
// not speed). Tighter, farm-calibrated floors that would catch SLOWER automation are external data.
var minHumanCaptchaSolve = map[CaptchaKind]time.Duration{
	CaptchaText:        600 * time.Millisecond, // decode distorted glyphs + type them
	CaptchaMath:        350 * time.Millisecond, // read + compute + type (trivial arithmetic is fast for a human)
	CaptchaImageSelect: 500 * time.Millisecond, // perceive the grid + click the matching tiles
	CaptchaImageDoodle: 500 * time.Millisecond,
	CaptchaClock:       800 * time.Millisecond, // read the analog hands + type the time
}

// sliderClaimMarginMs is the clock/network slack when comparing the client's CLAIMED drag duration (trajectory
// t-values, which a synthesizer can pad) to the SERVER-OBSERVED solve time (issue->verify, unforgeable). Beyond
// it, a trajectory claiming MORE drag-time than the whole solve window is impossible for a real drag (which
// happens WITHIN it). FP-safe by construction: a real drag's duration is always <= the server-observed elapsed.
const sliderClaimMarginMs = 150.0

// queueActFloor is the PHYSIOLOGICAL floor on a virtual-queue admission->action: no human perceives "you're in"
// and completes the protected action faster than this (reaction + read + move + click). A faster admission->action
// is an automated position-holder that polled and acted instantly. FP-safe — a LOWER bound, so a slow, distracted,
// or backgrounded-tab human who acts late is never flagged.
const queueActFloor = 600 * time.Millisecond

func classOf(s string) pow.Class {
	switch s {
	case "many-small":
		return pow.ClassManySmall
	case "memory-hard":
		return pow.ClassMemoryHard
	default:
		return pow.ClassHashcash
	}
}

// powLevelParams maps a PoW class + difficulty level to (bit-difficulty, sub-puzzle count, Argon2 memory KiB).
// It is the COST dial for the proof-of-work gates: harder = more hashing / more sub-puzzles / more memory. The
// SHA-256 classes (hashcash/many-small) carry a high bit-target; memory-hard stays LOW-bit because each
// Argon2id evaluation already costs ~1000x a SHA-256 hash, and scales its memory instead.
func powLevelParams(class pow.Class, lv Level) (difficulty, count int, memKiB uint32) {
	switch class {
	case pow.ClassMemoryHard:
		switch lv {
		case LevelEasy:
			return 6, 1, 4096
		case LevelHard:
			return 10, 1, 16384
		default:
			return 8, 1, 8192
		}
	case pow.ClassManySmall:
		switch lv {
		case LevelEasy:
			return 8, 8, 8192
		case LevelHard:
			return 12, 24, 8192
		default:
			return 10, 16, 8192
		}
	default: // hashcash (count is unused for a single-puzzle class). Kept in-browser-solvable: the JS solver
		// awaits one SHA-256 digest per attempt, so bits stay modest (a higher target would take minutes).
		switch lv {
		case LevelEasy:
			return 12, 1, 8192
		case LevelHard:
			return 18, 1, 8192
		default:
			return 15, 1, 8192
		}
	}
}

// NewMux builds the arena gate HTTP surface under /arena/*, signing tokens with secret and tracking issued
// nonces for single-use (replay) resistance. The challenge wire format is the pow.Challenge JSON the
// reference solver already understands; verify returns {ok, token}.
func captchaKindOf(s string) CaptchaKind {
	switch s {
	case "math":
		return CaptchaMath
	case "honeypot":
		return CaptchaHoneypot
	case "image-select":
		return CaptchaImageSelect
	case "image-doodle":
		return CaptchaImageDoodle
	case "image-shapes":
		return CaptchaImageShapes
	case "clock":
		return CaptchaClock
	default:
		return CaptchaText
	}
}

func NewMux(secret []byte) http.Handler {
	store := pow.NewNonceStore()
	captchas := newCaptchaStore()
	audios := newCaptchaStore()
	spatials := newCaptchaStore()
	queues := newQueueStore()
	tracks := newTrackStore()
	issuer := NewPACTIssuer()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /arena/challenge", func(w http.ResponseWriter, r *http.Request) {
		class := classOf(r.URL.Query().Get("gate"))
		// Difficulty is a COST dial (easy/medium/hard) — more work, never a better bot/human test (see levels.go).
		// Memory-hard uses a LOW bit-target because each Argon2id evaluation is ~1000x costlier than a SHA-256 hash.
		diff, count, memKiB := powLevelParams(class, ParseLevel(r.URL.Query().Get("level")))
		if v := r.URL.Query().Get("difficulty"); v != "" { // explicit override (capped) for power users
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= MaxDifficulty {
				diff = n
			}
		}
		c, err := pow.Mint(class, diff, count, memKiB, 1)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		store.Issue(c)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c)
	})

	mux.HandleFunc("POST /arena/verify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			pow.Challenge
			Counters []uint64 `json:"counters"`
		}
		// Bound the request body so a hostile client can't stream an unbounded payload at the gate.
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		c, sol := body.Challenge, pow.Solution{Counters: body.Counters}
		token, ok := pow.CheckSolution(secret, c, sol)
		// Server-observed solve RATE (hashes tried / issue->verify elapsed), measured BEFORE Redeem consumes the
		// nonce. Telemetry only — the absolute rate is hardware-dependent (see minMeasurableHashes), so it is not a
		// standalone conviction; a hardware-aware detector can join it to the claimed core count later.
		var solveHPS float64
		if ok {
			if age, aged := store.Age(c.Nonce); aged && age >= minMeasurableSolve {
				var hashes float64
				for _, ct := range body.Counters {
					hashes += float64(ct)
				}
				if hashes >= minMeasurableHashes {
					solveHPS = hashes / age.Seconds()
				}
			}
			// Single-use: the nonce must be outstanding at >= the claimed difficulty, then it is consumed, so a
			// solver cannot replay a token or downgrade the difficulty.
			ok = store.Redeem(c.Nonce, c.Difficulty)
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"ok": ok, "gate": string(c.Class)}
		if ok {
			resp["token"] = token
		}
		if solveHPS > 0 {
			resp["solve_hps"] = solveHPS
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// --- CATALOG: the machine-readable manifest of the CAPTCHA challenge space (kinds x levels x fonts/categories)
	// so a red-teamer can iterate the whole bench programmatically. Assembled from the live sources — never drifts. ---
	mux.HandleFunc("GET /arena/catalog", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(arenaCatalog())
	})

	// --- CAPTCHA gates: same shape as PoW (issue → answer → verify → single-use token), but the "work" is a
	// human-readable test. Self-hosted, generic reproductions of documented mechanisms — not a vendor clone. ---
	mux.HandleFunc("GET /arena/captcha", func(w http.ResponseWriter, r *http.Request) {
		c, answer := MintCaptcha(captchaKindOf(r.URL.Query().Get("kind")), ParseLevel(r.URL.Query().Get("level")), r.URL.Query().Get("font"), r.URL.Query().Get("charset"))
		captchas.put(c.ID, answer)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c) // the answer is NOT serialised — only the public challenge is sent
	})

	mux.HandleFunc("POST /arena/captcha/verify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Kind   CaptchaKind `json:"kind"`
			ID     string      `json:"id"`
			Answer string      `json:"answer"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		// take() consumes the id (single-use): an unknown or already-redeemed id fails, so a token cannot
		// be replayed and an answer cannot be brute-forced against a live challenge across requests.
		expected, age, known := captchas.take(body.ID)
		ok := known && CheckCaptcha(body.Kind, expected, body.Answer)
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"ok": ok, "kind": string(body.Kind)}
		if ok {
			resp["token"] = SignCaptchaToken(secret, body.Kind, body.ID)
			// Server-observed solve time. A CAPTCHA answered CORRECTLY faster than a human can perceive+answer is
			// OCR/ML automation — human-time-bound (reading/typing), NOT compute-bound, so hardware-independent
			// (unlike the PoW hash-rate). The gate still passes; the anomaly rides the verdict so the detector
			// convicts a bot that solved it. floors are conservative physiological lower bounds (FP-safe: a slow
			// human is never flagged; no floor for honeypot, whose tell is the trap field not speed).
			resp["solve_ms"] = age.Milliseconds()
			if floor, has := minHumanCaptchaSolve[body.Kind]; has && age > 0 && age < floor {
				resp["anomaly"] = "solved_faster_than_human"
			}
		}
		// Honeypot trip: the challenge asks the client to leave a HIDDEN field empty. A human never sees it; a
		// naive form-filling bot completes it, so a non-empty answer (the trap value) is an unambiguous bot — the
		// gate fails (ok=false) but the anomaly rides the verdict so the SESSION convicts. FP-safe by construction
		// (a real user cannot fill a field they are never shown). Gated on `known` so a garbage/replayed id can't
		// synthesize the tell against a session.
		if known && body.Kind == CaptchaHoneypot && strings.TrimSpace(body.Answer) != "" {
			resp["anomaly"] = "honeypot_filled"
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// --- AUDIO gate: the ASR-benchmark twin of the text (OCR) + image (CV) gates. Same shape (issue clip →
	// transcribe → verify → single-use token), but the challenge is a spoken-digit WAV synthesised in pure Go
	// from an embedded CC-BY-SA FSDD corpus. The answer never leaves the server; only the distorted clip does. ---
	mux.HandleFunc("GET /arena/audio", func(w http.ResponseWriter, r *http.Request) {
		a, answer := MintAudio(ParseLevel(r.URL.Query().Get("level")))
		audios.put(a.ID, answer)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a) // the answer is NOT serialised — only the clip + prompt are sent
	})

	mux.HandleFunc("POST /arena/audio/verify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID     string `json:"id"`
			Answer string `json:"answer"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		expected, age, known := audios.take(body.ID) // single-use: no replay, no cross-request brute force
		ok := known && CheckAudio(expected, body.Answer)
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"ok": ok, "kind": "audio"}
		if ok {
			resp["token"] = SignCaptchaToken(secret, "audio", body.ID)
			// Server-observed solve time. A human must PLAY the clip in real time before answering; an ASR solver
			// batch-transcribes it in milliseconds. A CORRECT answer faster than the clip's real-time listen floor
			// (len × 450ms, under FSDD's ~600ms/digit playback) is automation — the gate still passes, the anomaly
			// rides the verdict so the session convicts. FP-safe: no human answers an N-digit clip before hearing it.
			resp["solve_ms"] = age.Milliseconds()
			if floor := time.Duration(len(expected)) * 450 * time.Millisecond; age > 0 && age < floor {
				resp["anomaly"] = "solved_faster_than_audio"
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// --- SPATIAL gate: the Arkose/FunCaptcha 3D-object family. A grid of isometric cubes at random orientations;
	// select every cube with the target colour on TOP. Perceive-and-click like image-select, so it shares the
	// solved_faster_than_human floor + the arena_captcha_superhuman join. The answer stays server-side. ---
	mux.HandleFunc("GET /arena/spatial", func(w http.ResponseWriter, r *http.Request) {
		s, answer := MintSpatial(ParseLevel(r.URL.Query().Get("level")))
		spatials.put(s.ID, answer)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s) // the answer (matching indices) is NOT serialised
	})

	mux.HandleFunc("POST /arena/spatial/verify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID       string `json:"id"`
			Selected []int  `json:"selected"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		expected, age, known := spatials.take(body.ID) // single-use: no replay, no cross-request guessing
		ok := known && CheckSpatial(expected, body.Selected)
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"ok": ok, "kind": "spatial"}
		if ok {
			resp["token"] = SignCaptchaToken(secret, "spatial", body.ID)
			// A correct grid selection faster than a human can perceive the tiles + click is automation (the same
			// human-time floor as image-select) — the gate passes, the anomaly rides the verdict so the session
			// convicts on coherence via bh.arena_captcha_superhuman. FP-safe: humans take seconds on a tile grid.
			resp["solve_ms"] = age.Milliseconds()
			if age > 0 && age < 500*time.Millisecond {
				resp["anomaly"] = "solved_faster_than_human"
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// --- SLIDER captcha (GeeTest-style): drag the piece into the gap; the gate verifies the drop position AND
	// the drag trajectory's behavioural plausibility (the uniform-velocity discriminator). On-thesis, owned. ---
	mux.HandleFunc("GET /arena/slider", func(w http.ResponseWriter, r *http.Request) {
		s, state := MintSlider(ParseLevel(r.URL.Query().Get("level")))
		captchas.put(s.ID, state)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s)
	})

	mux.HandleFunc("POST /arena/slider/verify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID         string        `json:"id"`
			X          float64       `json:"x"`
			Trajectory []SliderPoint `json:"trajectory"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		state, age, known := captchas.take(body.ID) // single-use; state is "gapX:level"; age = server solve time
		w.Header().Set("Content-Type", "application/json")
		if !known {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "kind": "slider", "reason": "unknown or used"})
			return
		}
		gapStr, lvStr, _ := strings.Cut(state, ":")
		gap, _ := strconv.Atoi(gapStr)
		ok, reason := CheckSlider(gap, body.X, body.Trajectory, sliderParams(ParseLevel(lvStr)))
		resp := map[string]any{"ok": ok, "kind": "slider", "reason": reason}
		if ok {
			resp["token"] = SignCaptchaToken(secret, "slider", body.ID)
			// Client-claim vs server-truth coherence: the "drag too fast" check trusts the client's trajectory
			// t-values, which a synthesizer can PAD. The SERVER-OBSERVED solve time (issue->verify) cannot be
			// faked. A trajectory claiming MORE drag-time than the whole solve window is impossible (the drag
			// happens WITHIN it) — a padded trajectory submitted near-instantly. FP-safe: a real drag's duration
			// is always <= the server-observed elapsed. Rides the verdict for the detector to convict the session.
			if n := len(body.Trajectory); n >= 2 && age > 0 {
				trajMs := body.Trajectory[n-1].T - body.Trajectory[0].T
				if trajMs > age.Seconds()*1000+sliderClaimMarginMs {
					resp["anomaly"] = "trajectory_exceeds_solve_time"
				}
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// --- ROTATE captcha (Arkose-style): drag the object upright; the gate scores the rotation TRAJECTORY
	// (a bare angle no longer passes — same behavioural discriminator as the slider). On-thesis, owned. ---
	mux.HandleFunc("GET /arena/rotate", func(w http.ResponseWriter, req *http.Request) {
		rc, state := MintRotate(ParseLevel(req.URL.Query().Get("level")))
		captchas.put(rc.ID, state)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rc)
	})

	mux.HandleFunc("POST /arena/rotate/verify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID         string        `json:"id"`
			Trajectory []RotatePoint `json:"trajectory"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		lvStr, age, known := captchas.take(body.ID) // single-use; stored value is the level; age = server solve time
		w.Header().Set("Content-Type", "application/json")
		if !known {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "kind": "rotate", "reason": "unknown or used"})
			return
		}
		ok, reason := CheckRotate(body.Trajectory, rotateParams(ParseLevel(lvStr)))
		resp := map[string]any{"ok": ok, "kind": "rotate", "reason": reason}
		if ok {
			resp["token"] = SignCaptchaToken(secret, "rotate", body.ID)
			// Same client-claim vs server-truth coherence as the slider: a rotation trajectory claiming more
			// drag-time than the whole server-observed solve is a synthesized trajectory submitted near-instantly.
			// FP-safe: a real rotation's duration is always <= the server-observed elapsed.
			if n := len(body.Trajectory); n >= 2 && age > 0 {
				trajMs := body.Trajectory[n-1].T - body.Trajectory[0].T
				if trajMs > age.Seconds()*1000+sliderClaimMarginMs {
					resp["anomaly"] = "trajectory_exceeds_solve_time"
				}
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// --- WAITING-ROOM / VIRTUAL QUEUE (Queue-it / Cloudflare Waiting Room family): issue a position, admit after
	// a controlled wait, then take the protected action. Not a puzzle — a fairness/rate mechanism. The detector
	// reads the WAIT-behaviour: a scalper bot polls admission and acts in ms; a human reads "you're in" and acts
	// in seconds. On-thesis, owned infra. ---
	mux.HandleFunc("GET /arena/queue", func(w http.ResponseWriter, r *http.Request) {
		wait := queueAdmitWait(ParseLevel(r.URL.Query().Get("level")))
		id := randHex(16)
		pos := queues.issue(id, wait, time.Now())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"kind": "queue", "id": id, "position": pos, "admit_after_ms": wait.Milliseconds(),
		})
	})

	mux.HandleFunc("GET /arena/queue/status", func(w http.ResponseWriter, r *http.Request) {
		admitted, pos, known := queues.status(r.URL.Query().Get("id"), time.Now())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"kind": "queue", "admitted": admitted, "position": pos, "known": known})
	})

	mux.HandleFunc("POST /arena/queue/act", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		elapsed, admitted, known := queues.act(body.ID, time.Now())
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"kind": "queue"}
		if !known || !admitted {
			// Acted before admission (or an unknown/used ticket) — the client never completed the wait.
			resp["ok"] = false
			resp["reason"] = "not admitted"
			// A KNOWN ticket acted on BEFORE its admission wait elapsed is a deliberate queue-skip: a human's page
			// only enables the action after /status reports admitted, so only a script POSTs /act early. FP-safe by
			// construction. The gate fails, but the anomaly rides the verdict so the session convicts (like honeypot).
			if known {
				resp["anomaly"] = "queue_bypass"
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		resp["ok"] = true
		resp["token"] = SignCaptchaToken(secret, "queue", body.ID)
		resp["act_ms"] = elapsed.Milliseconds()
		// SERVER-OBSERVED admission->action: faster than a human can perceive "you're in" and act is an automated
		// position-holder. The gate still passes; the anomaly rides the verdict so the detector convicts the session.
		if elapsed < queueActFloor {
			resp["anomaly"] = "acted_faster_than_human"
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// --- TRACK / moving-target: the LLM-agent STALE-SNAPSHOT probe. A target moves; the client must click its
	// CURRENT position. A human tracks it live; a snapshot-then-slowly-reason agent clicks the STALE (seconds-old)
	// position it saw at snapshot time — the one behavioral signal that survives a coherent fingerprint. ---
	mux.HandleFunc("GET /arena/track", func(w http.ResponseWriter, r *http.Request) {
		id := randHex(16)
		base, span := trackSpeedForLevel(ParseLevel(r.URL.Query().Get("level")))
		x, y, vx, vy := tracks.issue(id, time.Now(), base, span)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"kind": "track", "id": id, "x": x, "y": y, "vx": vx, "vy": vy, "canvas": trackCanvas,
		})
	})

	// The rendered widget: a human tracks the animated dot and clicks it live; a text-snapshot agent freezes the
	// dot's position and clicks it stale after reasoning. Same-origin fetches ride the detector relay (ks_sid join).
	mux.HandleFunc("GET /arena/track/play", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(trackWidgetHTML))
	})

	mux.HandleFunc("GET /arena/track/pos", func(w http.ResponseWriter, r *http.Request) {
		x, y, known := tracks.current(r.URL.Query().Get("id"), time.Now())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"kind": "track", "x": x, "y": y, "known": known})
	})

	mux.HandleFunc("POST /arena/track/verify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID string  `json:"id"`
			X  float64 `json:"x"`
			Y  float64 `json:"y"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		hit, stale, known := tracks.verify(body.ID, body.X, body.Y, time.Now())
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"kind": "track", "ok": hit, "known": known}
		// A click on the target's SECONDS-OLD position (far from where it is now) is a stale-snapshot action: no
		// human acts on a >1.2s-old view (they re-perceive before acting), only a snapshot-then-slowly-reason LLM
		// agent does. The anomaly rides the verdict so the detector convicts the session (like the other gates).
		if stale {
			resp["anomaly"] = "stale_snapshot"
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// --- PACT / Private Access Token: a valid anonymous PERSONHOOD token skips the challenge. The issuer mints
	// freely here (no real attestation in-sandbox) — so this also demonstrates the bypass: any client can get a
	// token, yet the detector still convicts a no-JS one on coherence (the honest caveat, like Web Bot Auth). ---
	mux.HandleFunc("GET /arena/pact", func(w http.ResponseWriter, _ *http.Request) {
		nonce := randHex(16)
		expires := time.Now().Add(5 * time.Minute).Unix()
		captchas.put("pact:"+nonce, "") // track for single-use redemption
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":   issuer.Issue(nonce, expires),
			"expires": expires,
			"note":    "anonymous proof-of-personhood token — present it at /arena/pact/verify to skip the challenge",
		})
	})

	mux.HandleFunc("POST /arena/pact/verify", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		ok, nonce, reason := issuer.Verify(body.Token, time.Now().Unix())
		if ok {
			_, _, known := captchas.take("pact:" + nonce) // single-use: a token cannot be replayed
			ok = known
			if !known {
				reason = "token already redeemed"
			}
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"ok": ok, "decision": "challenge", "reason": reason}
		if ok {
			resp["decision"] = "allow" // valid personhood token ⇒ skip the challenge (the PACT behaviour)
			resp["token"] = SignCaptchaToken(secret, "pact", nonce)
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// Rate-limit gate (the documented CDN/WAF token-bucket): 200 under the per-level RPS budget, 429 above it.
	// A rate-BASED challenge gate — what RPS reconnaissance (harness rps_scout) ramps against to find the knee.
	// One limiter per level, keyed by client origin, so the budget is per-source and survives across requests.
	rateLimiters := map[Level]*rateLimiter{}
	for _, lv := range []Level{LevelEasy, LevelMedium, LevelHard} {
		limit, burst := rateParams(lv)
		rateLimiters[lv] = newRateLimiter(limit, burst)
	}
	mux.HandleFunc("GET /arena/rate", func(w http.ResponseWriter, r *http.Request) {
		lv := ParseLevel(r.URL.Query().Get("level"))
		if !rateLimiters[lv].allow(clientIP(r), time.Now()) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded — too many requests", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "level": string(lv), "note": "under the rate budget"})
	})

	mux.HandleFunc("GET /arena/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	return mux
}
