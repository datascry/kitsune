# The Arena — challenge gates ⇄ the detector

The **arena** is Kitsune's public, self-hosted reproduction of documented **open** web challenge mechanisms.
A visitor brings any client (browser, bot, or their own solver) to a gate, tries to pass it, and sees **two
verdicts at once**:

- the **gate verdict** — did you solve the challenge?
- the **detector verdict** — does your client *cohere* across layers, read independently over the edge?

The point the arena makes live: **a solved challenge is a cost or Turing test, not a bot/human
discriminator.** A script can pass any gate here and still be convicted on the network layer. **Coherence +
attestation is the durable signal, not the puzzle.** Every gate falls to the right evader; the detector
convicts the no-JS client regardless.

**One refinement — the `track` gate.** It is the exception that proves where the puzzle *is* a discriminator:
against an **LLM browser agent** (a real, coherent, humanly-paced browser that evades every fingerprint and
behavioural tell), a **real-time visual-tracking** task convicts by construction — the agent's
snapshot→reason(seconds)→act loop clicks a stale position while a human servos to the live one. The physics of
the loop, not its cognition, is the tell. (A plain script still "beats" `track` by computing the motion — and is
convicted on fingerprint, exactly as the thesis predicts.)

It is the lab's **ethics boundary made concrete**: the arena gates and the reference solvers only ever talk
to Kitsune's *own* infrastructure (the `arena` Go service, relayed by the detector). They never contact,
proxy to, or solve a third-party challenge (Cloudflare Turnstile, reCAPTCHA, hCaptcha). The gates reproduce
the documented *mechanism* of each family — they are vendor-neutral, not branded-widget clones.

## Where it lives

| Piece | Path | Role |
|---|---|---|
| Gate service | `arena/` (Go) | Mints + verifies every gate; reuses `evaders/pow` PoW primitives via a `replace`. Owned infra only. |
| Relay + pages | `detector/src/kitsune_detector/app.py`, `arena_page.py` | The detector relays `/arena/*` to `KITSUNE_ARENA_URL` and serves the `/arena` pages so a visitor hits one origin through the edge (the gate verdict joins the detector verdict on `ks_sid`). |
| Solvers (red) | `evaders/arena-solver` (Go), `evaders/arena-solver-ocr` (Python TrOCR) | Browserless solvers, allow-list-scoped to our own gates. |

**Routing.** `/arena` is the index (a card per gate); each gate has its **own auto-serving page** at
`/arena/gate/<slug>` with that one challenge's widget + the dual verdict + its HTTP endpoints (so a bypass
tester can script straight against it). The challenge serves itself on page load — no "run" button.

## The gate catalog

Every gate with a real difficulty axis offers **easy / medium / hard** (see *Difficulty* below); honeypot,
pact, checkbox and managed are coherence/binary-gated and have no level dial.

| Gate (`slug`) | Family (documented, open) | Mechanism | Beaten by | Levels |
|---|---|---|---|---|
| `checkbox` | reCAPTCHA-v2 / Turnstile checkbox | "Verify you are human" — the click triggers a silent coherence check; coherent ⇒ pass-on-click, else step-up PoW | coherent client passes; a no-JS solver is convicted by the detector | — |
| `managed` | Turnstile-style ladder | silent coherence verdict → non-interactive PoW step-up | same as checkbox (the silent face) | — |
| `hashcash` | Proof-of-work · anubis | SHA-256 leading-zeros | in-browser / scripted SHA-256 solver | 12 / 15 / 18 bits |
| `many-small` | Proof-of-work · friendly-captcha | N small SHA-256 sub-puzzles | per-sub solver | 8×8 / 10×16 / 12×24 |
| `memory-hard` | Proof-of-work · Argon2id | memory-hard hashcash | reference Argon2id solver (costly by design) | 4 / 8 / 16 MB |
| `text` | CAPTCHA · distorted image | warped, overlapping, noise-crossed glyphs (answer in pixels) | **real OCR** (`arena-solver-ocr`, TrOCR) — the Go heuristic fails | 4 / 5 / 6 chars + noise |
| `math` | CAPTCHA · logic | arithmetic | scripted parse+compute (`+`,`−`,`×`) | `+` / `+−×` / large `×` |
| `clock` | CAPTCHA · read-the-clock | read an **analog clock face** rendered at a random time + type it (H:MM) — owned procedural, a visual-reasoning task (interpret the hour/minute hands) beyond glyph OCR | a ray-casting hand-angle reader (owned geometry); real clock CAPTCHAs need robust CV | easy / medium / hard (noise) |
| `honeypot` | CAPTCHA · hidden field | a trap field that must stay empty | leave it empty | — |
| `audio` | reCAPTCHA / hCaptcha audio (accessibility) | transcribe a spoken-digit WAV (embedded CC-BY-SA FSDD corpus, pure-Go synth + noise/tone/overlap); the ASR-benchmark twin of `text`/OCR. A correct answer faster than the clip's real-time playback is ASR automation (`bh.arena_audio_superhuman`, server-observed) | real ASR (Whisper) — the matched-filter reference solver beats easy but not medium/hard | easy / medium / hard (distortion) |
| `slider` | CAPTCHA · GeeTest drag | drop position **+ drag-trajectory** velocity check | variable-velocity trajectory synthesis | tolerance + trajectory bar |
| `image-select` | CAPTCHA · reCAPTCHA-v2 | "select every animal" over **emoji glyph** tiles | **real CV/VLM** — the radial-shape heuristic fails | 6 / 9 tiles + noise |
| `doodle` | CAPTCHA · reCAPTCHA-v2 | same, over **Quick, Draw! sketch** tiles | **real CV/VLM** (harder than emoji) | 6 / 9 tiles + noise |
| `rotate` | CAPTCHA · Arkose / FunCaptcha | drag the object upright; **rotation-trajectory** scored | variable-rate drag synthesis | angle tolerance + trajectory bar |
| `spatial` | Arkose / FunCaptcha **3D object** | select every isometric cube with the target colour on **top** — a grid of cubes at random 3D orientations (identify the rotated top face, not a 2D glyph; owned procedural, zero-license). A correct selection faster than a human can scan the grid convicts (`bh.arena_captcha_superhuman`) | a top-face colour-sampler beats the owned geometry; real Arkose needs 3D CV | 6 / 9 tiles + noise |
| `shell` | **Track-under-occlusion (anti-LLM)** | watch a ball hidden under one of N cups through a server-defined shuffle, then click its final cup — an ORIGINAL gate, not a wild-captcha clone. A correct answer faster than the shuffle runtime was precomputed from the swap payload, not watched (`bh.arena_shell_precomputed`); the snapshot->reason->act agent can't follow the occluded ball | a human watching the shuffle (a payload-replay bot is convicted) | cups + shuffle length/speed |
| `timing` | **Motor-timing precision (Grillmaster)** | press and hold each of N targets for its shown duration within tolerance — an ORIGINAL gate, not a wild-captcha clone. The release-error std across targets convicts a bot: superhuman precision (target-exact or a flat constant offset collapse the std to ~0), OR claiming more total hold time than the server-observed solve took (`bh.arena_timing_superhuman`) | a human (irreducible motor jitter + real elapsed) | tolerance + target count |
| `keymap` | **Broken/remapped keyboard (input-integrity)** | the keys silently produce other characters — discover the mapping by probing, then type the target — an ORIGINAL gate, not a wild-captcha clone. A correct answer with ZERO exploration (no backspaces) means the client decoded the remap from the payload rather than probing it, and a solve faster than the discover+type floor also convicts (`bh.arena_keymap_no_exploration`) | a human (a hidden remap needs probing + corrections) | remap size + target length |
| `image-shapes` | CAPTCHA · reCAPTCHA-v2 | "select every &lt;shape&gt;" over **owned procedural geometric** tiles (zero-license) | shape classifier / VLM | 6 / 9 tiles + noise |
| `presshold` | **Press-and-hold** · Cloudflare "Press & Hold" / DataDome / HUMAN | hold one button for the shown duration, then release; the **held-pointer tremor** convicts a scripted hold — a real hand drifts (non-zero jitter floor) while an injected hold pins its samples to one coordinate (variance ~0), and claiming a longer hold than the whole solve window is impossible (`bh.arena_hold_robotic`) | a human (a real hand drifts + spends the time) | hold duration + tolerance |
| `sequence` | **Ordered click-in-sequence** · GeeTest icon-order / NetEase Yidun | click N numbered tiles at shuffled positions in numeric order; solving faster than a human can visually locate + click N ordered targets (age &lt; N × a per-target floor), or with a **metronomic** fixed-delay cadence, convicts (`bh.arena_seqclick_superhuman`) — the ordering + timing are the tell, not the puzzle | a human (visual-search + a varied pace) | tile count |
| `locate` | **Point localization** · hCaptcha "click the center of X" / AWS WAF | click the **center** of the named target among distractors on a free canvas (the centre is server-side, so passing needs real CV/visual location); a solver that computes the centroid clicks it **pixel-perfect** (distance &lt; 2.5px, below human aim variance), or solves faster than a human can locate+aim — either convicts (`bh.arena_localize_superhuman`) | a human (aims by eye, spreads tens of px) | distractor count + noise |
| `match` | **Orientation match / odd-one-out** · Arkose "faces the same way" / hCaptcha "which go together" | click the candidate arrow facing the same way as the reference — a **relational** task (compare reference vs each candidate, not classify one tile); per-tile jitter defeats a pixel-hash so real orientation reasoning is needed; solving faster than a human can scan a reference + N candidates convicts (`bh.arena_match_superhuman`) | a human (scans + compares) | tile count + noise |
| `slide` | **Sliding-tile puzzle** · KeyCAPTCHA / 15-puzzle | slide the 8-puzzle (3×3) into order; an **optimal plan** — the exact BFS-minimum move count on a non-trivial scramble, which a human wandering never hits — or solving faster than a human can slide the tiles convicts (`bh.arena_slide_superhuman`) | a human (wanders, suboptimal, spends the time) | scramble depth |
| `pattern` | **Trace the pattern** · connect-the-dots / Android pattern-lock | draw one stroke through N waypoints in order; a synthetic stroke hugs the ideal polyline with **~0 deviation** (too straight for a human hand, which wobbles), or draws faster than a human can move through the waypoints — either convicts (`bh.arena_pattern_superhuman`) — a distinct **path-fidelity** tell | a human (wobbly stroke, spends the time) | waypoint count |
| `reaction` | **Click when green** · reaction-time / "click when ready" | click the box the instant it turns green; the server-observed **reaction latency** (age − shown delay) below the human physiological floor (~150ms), or negative (a click reaching the server before the go — anticipation), convicts (`bh.arena_reaction_superhuman`) — a distinct **reaction-latency** tell, unforgeable in the too-fast direction | a human (reacts in ~250ms) | pre-cue delay |
| `spotdiff` | **Spot the difference** | two near-identical panels differ in K spots; click each difference on the right panel; a bot **pixel-diffs** the panels and clicks the exact centroid of each change (dist &lt; 3px) and finds them all instantly, while a human eyeballs (approximate) and needs seconds per difference — either convicts (`bh.arena_spotdiff_superhuman`) | a human (approximate clicks, slow) | shape + difference count |
| `track` | **Real-time visual tracking (anti-LLM-agent)** | click the **moving** dot; a snapshot→reason→act agent clicks the seconds-old position it last saw | a **human** (live visual servo) passes; an **LLM browser agent is CAUGHT** (`bh.arena_stale_snapshot`) — the one gate that convicts a *coherent, well-reasoned* agent, by the physics of its loop | easy / medium / hard (dot speed) |
| `queue` | Defense · virtual waiting-room | admission only after a controlled wait; act-before-admission + position-hoarding are server-observed | wait for admission (a bot that skips the wait or hoards positions is convicted) | admission wait |
| `rate` | Defense · rate-limit | per-origin request budget over a window | stay under the budget | budget / window |
| `pact` | Defense · Private Access Tokens | an anonymous Ed25519 proof-of-personhood token **skips** the challenge | present a token → skip (the documented bypass) — detector still convicts a no-JS one | — |

`pact` is the human-personhood twin of the shipped Web Bot Auth good-bot identity (`net.web_bot_auth_*`):
both are "claimed identity vs cryptographic proof." Honest caveat — the lab issuer mints freely (no real
device attestation in-sandbox), so any client can obtain a token and skip; real PACT issuers gate on a secure
enclave, which is external to the lab.

## Difficulty — a cost dial, not a security dial

Difficulty (`?level=easy|medium|hard`, default medium; a junk value falls back to medium) is **honest about
what it changes**: more PoW work, heavier text distortion, more tiles + noise, tighter fit. It raises the
attacker's **cost**, never the bot/human discrimination — **the detector's coherence verdict is unchanged at
every tier.** For the behavioural gates (`slider`/`rotate`) the velocity-CV **human-detection floor is held
constant** across levels (it's grounded on real human data); difficulty only tightens tolerance and asks for
a richer — but still human-reachable — trajectory, so a harder level never false-positives a real person.

PoW levels are kept in-browser-solvable (hashcash 12→18 bits) because the page's SubtleCrypto solver awaits
one digest per attempt; higher targets would take minutes. The cost gradient is real (≈15 ms → ≈550 ms).

## Image sources + licences

The image-select family uses **real, licence-clean public art** rendered to tiles (the old synthetic
shapes were readable by a radial classifier):

- **emoji** — Noto Emoji, **SIL OFL 1.1** (`arena/assets/NotoEmoji.ttf` + `OFL.txt`); no per-image
  attribution on rendered output. Single-codepoint glyphs, categorised by the Unicode taxonomy.
- **doodle** — Google **Quick, Draw!**, **CC BY 4.0** (`arena/assets/quickdraw.ndjson`, a 144-drawing
  de-identified sample of stroke vectors only; credit in `quickdraw.ATTRIBUTION.txt` + the gate blurb).

Traps deliberately avoided (verified at source): CIFAR-10/100 (no licence + withdrawn parent corpus),
ImageNet / Tiny-ImageNet (non-commercial, per-image ©), Unsplash / Pexels / Pixabay (proprietary "free" —
bans re-compiling into a service), OpenMoji (CC BY-SA ShareAlike — viral copyleft).

## Evasion status (the red side)

Two browserless solvers, both allow-list-scoped to our own gates:

- `arena-solver` (Go, stdlib) beats **math** (parse), **honeypot** (empty), **slider/rotate** (trajectory
  synthesis), and PoW (SHA-256). It is **held to those** — the hardened **text** gate needs real OCR, and the
  **image-select / doodle** gates broke its radial-shape classifier (they need a real CV/VLM).
- `arena-solver-ocr` (Python, HuggingFace TrOCR `anuashok/ocr-captcha-v3`) beats the **text** gate at every
  level — even hard (6 confusable chars + heavy noise); a charset clean-up strips the model's occasional
  stray separator.
- The **`track`** gate has no solver here *by design* — it is the one gate built to **catch**, not cost. A human
  passes it (live visual tracking); an **LLM browser agent is convicted** (`bh.arena_stale_snapshot`), validated
  live end-to-end (a claude-driven agent reasoned ~22s then clicked a stale position → caught; a realistic human
  proxy solves 9-10/10 with zero false convictions). A motion-computing *script* passes it — and is convicted on
  fingerprint, exactly as the thesis predicts.

The image-select hardening is the on-thesis move: the gate got harder than the heuristic solver, forcing a
real CV/VLM (the frontier) — and at the end of every chain the **detector convicts the no-JS client anyway**.

## Which gate addresses which adversary archetype

Gates impose **cost**; the **detector convicts** (see `kitsune_harness.archetypes` + `task archetype-validate`).
Together they cover the persona ladder:

| Archetype | Detector verdict | Gate(s) that price it | Public mechanism reproduced |
|---|---|---|---|
| credential-stuffer | caught (fp_collision) | `rate` + PoW + `checkbox`/captcha | rate-limit · Turnstile · mCaptcha |
| scalper | caught (fp_collision) | `rate` + PoW + `queue` | rate-limit · PoW · waiting-room |
| scraper | caught (fp_collision) | `rate` + PoW/page | rate-limit · Turnstile |
| review-farmer | caught (trace_collision) | captcha + `slider` (behavioral) | behavioral biometrics |
| proxy-botnet | caught (shared_origin) | `rate` (per-origin) + IP-rep | IP reputation · PAT |
| **sybil-farmer** | **candidate — evades detection** | **`pact`** | **Private Access Tokens** |
| **llm-browser-agent** | **evades detection** (real browser ⇒ coherent fp, humanly paced, aligned) | **`track`** | **real-time visual tracking** |

The synthesis: **the gate addresses what detection can't.** Two archetypes evade fingerprint/behaviour
conviction, and each has a gate built for it:
- The `sybil-farmer` diversifies fingerprints → `candidate`. **`pact`** covers it — you can fake infinite
  fingerprints, but not N anonymous personhood tokens without N attested devices.
- The `llm-browser-agent` drives a *real* browser (coherent fingerprint), paces itself like a human, and (being
  aligned) walks through reasoning honeypots — it evades every per-session and behavioural tell. **`track`**
  covers it: a moving target it cannot hit, because its snapshot→reason(seconds)→act loop clicks a stale position
  while a human servos to the live one. The physics of the loop, not its cognition, is the tell.

The canonical scalper **waiting-room / virtual queue** (Queue-it / Cloudflare Waiting Room) is now reproduced as
the **`queue`** gate (admit after a controlled wait; act-before-admission and position-hoarding are server-observed),
fairer than `rate`'s hard 429.

## Ethics (enforced)

The evaders may target **only** Kitsune's own detector/arena + the approved public endpoints in
`harness/src/kitsune_harness/allowlist.py` (`is_allowed`). The arena gates reproduce documented open
mechanisms, vendor-neutral; there is no DoS/flood generator (the H2 DoS family is a *detection* model, not an
attack tool). See [architecture.md §13](architecture.md) — the self-contained arena *is* the ethics design.

## Deploy

The `arena` service ships in the production stack (`docker-compose.prod.yml` + the pull-based
`docker-compose.deploy.yml`); the detector relays to it via `KITSUNE_ARENA_URL=http://arena:8095`. Without
the arena container running, `/arena/*` returns 503/502. See [deploy.md](deploy.md).
