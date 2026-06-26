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
		// Per-class defaults: SHA-256 classes can afford a high bit-target; memory-hard uses a LOW target
		// because each Argon2id evaluation is ~1000x costlier than a SHA-256 hash (so a low target still costs).
		diff := 20
		count := 16 // friendlycaptcha-style sub-puzzle count
		var memKiB uint32 = 8192
		if class == pow.ClassMemoryHard {
			diff = 8
		}
		if v := r.URL.Query().Get("difficulty"); v != "" {
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
		c, answer := MintCaptcha(captchaKindOf(r.URL.Query().Get("kind")))
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
	mux.HandleFunc("GET /arena/slider", func(w http.ResponseWriter, _ *http.Request) {
		s, gap := MintSlider()
		captchas.put(s.ID, gap)
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
		gapStr, known := captchas.take(body.ID) // single-use
		w.Header().Set("Content-Type", "application/json")
		if !known {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "kind": "slider", "reason": "unknown or used"})
			return
		}
		gap, _ := strconv.Atoi(gapStr)
		ok, reason := CheckSlider(gap, body.X, body.Trajectory)
		resp := map[string]any{"ok": ok, "kind": "slider", "reason": reason}
		if ok {
			resp["token"] = SignCaptchaToken(secret, "slider", body.ID)
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// --- ROTATE captcha (Arkose-style): drag the object upright; the gate scores the rotation TRAJECTORY
	// (a bare angle no longer passes — same behavioural discriminator as the slider). On-thesis, owned. ---
	mux.HandleFunc("GET /arena/rotate", func(w http.ResponseWriter, _ *http.Request) {
		r, ans := MintRotate()
		captchas.put(r.ID, ans)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(r)
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
		_, known := captchas.take(body.ID) // single-use
		w.Header().Set("Content-Type", "application/json")
		if !known {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "kind": "rotate", "reason": "unknown or used"})
			return
		}
		ok, reason := CheckRotate(body.Trajectory)
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
