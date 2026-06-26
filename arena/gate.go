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
	default:
		return CaptchaText
	}
}

func NewMux(secret []byte) http.Handler {
	store := pow.NewNonceStore()
	captchas := newCaptchaStore()
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
		// Single-use: the nonce must be outstanding at >= the claimed difficulty, then it is consumed, so a
		// solver cannot replay a token or downgrade the difficulty.
		if ok {
			ok = store.Redeem(c.Nonce, c.Difficulty)
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"ok": ok, "gate": string(c.Class)}
		if ok {
			resp["token"] = token
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// --- CAPTCHA gates: same shape as PoW (issue → answer → verify → single-use token), but the "work" is a
	// human-readable test. Self-hosted, generic reproductions of documented mechanisms — not a vendor clone. ---
	mux.HandleFunc("GET /arena/captcha", func(w http.ResponseWriter, r *http.Request) {
		c, answer := MintCaptcha(captchaKindOf(r.URL.Query().Get("kind")), ParseLevel(r.URL.Query().Get("level")))
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
		expected, known := captchas.take(body.ID)
		ok := known && CheckCaptcha(body.Kind, expected, body.Answer)
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"ok": ok, "kind": string(body.Kind)}
		if ok {
			resp["token"] = SignCaptchaToken(secret, body.Kind, body.ID)
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
		state, known := captchas.take(body.ID) // single-use; state is "gapX:level"
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
		lvStr, known := captchas.take(body.ID) // single-use; stored value is the level
		w.Header().Set("Content-Type", "application/json")
		if !known {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "kind": "rotate", "reason": "unknown or used"})
			return
		}
		ok, reason := CheckRotate(body.Trajectory, rotateParams(ParseLevel(lvStr)))
		resp := map[string]any{"ok": ok, "kind": "rotate", "reason": reason}
		if ok {
			resp["token"] = SignCaptchaToken(secret, "rotate", body.ID)
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
			_, known := captchas.take("pact:" + nonce) // single-use: a token cannot be replayed
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

	mux.HandleFunc("GET /arena/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	return mux
}
