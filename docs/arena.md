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
| `honeypot` | CAPTCHA · hidden field | a trap field that must stay empty | leave it empty | — |
| `slider` | CAPTCHA · GeeTest drag | drop position **+ drag-trajectory** velocity check | variable-velocity trajectory synthesis | tolerance + trajectory bar |
| `image-select` | CAPTCHA · reCAPTCHA-v2 | "select every animal" over **emoji glyph** tiles | **real CV/VLM** — the radial-shape heuristic fails | 6 / 9 tiles + noise |
| `doodle` | CAPTCHA · reCAPTCHA-v2 | same, over **Quick, Draw! sketch** tiles | **real CV/VLM** (harder than emoji) | 6 / 9 tiles + noise |
| `rotate` | CAPTCHA · Arkose / FunCaptcha | drag the object upright; **rotation-trajectory** scored | variable-rate drag synthesis | angle tolerance + trajectory bar |
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

The image-select hardening is the on-thesis move: the gate got harder than the heuristic solver, forcing a
real CV/VLM (the frontier) — and at the end of every chain the **detector convicts the no-JS client anyway**.

## Which gate addresses which adversary archetype

Gates impose **cost**; the **detector convicts** (see `kitsune_harness.archetypes` + `task archetype-validate`).
Together they cover the persona ladder:

| Archetype | Detector verdict | Gate(s) that price it | Public mechanism reproduced |
|---|---|---|---|
| credential-stuffer | caught (fp_collision) | `rate` + PoW + `checkbox`/captcha | rate-limit · Turnstile · mCaptcha |
| scalper | caught (fp_collision) | `rate` + PoW | rate-limit · PoW · *waiting-room (gap)* |
| scraper | caught (fp_collision) | `rate` + PoW/page | rate-limit · Turnstile |
| review-farmer | caught (trace_collision) | captcha + `slider` (behavioral) | behavioral biometrics |
| proxy-botnet | caught (shared_origin) | `rate` (per-origin) + IP-rep | IP reputation · PAT |
| **sybil-farmer** | **candidate — evades detection** | **`pact`** | **Private Access Tokens** |

The synthesis: the `sybil-farmer` is the one archetype detection cannot convict (diversify fingerprints →
`candidate`). The **`pact`** gate covers exactly that — you can fake infinite fingerprints, but not N anonymous
personhood tokens without N attested devices. **The gate addresses what detection can't.** The one public
mechanism not yet reproduced is a **waiting-room / virtual queue** (Queue-it / Cloudflare Waiting Room) — the
canonical scalper defense (admit N/sec, queue the rest), fairer than `rate`'s hard 429.

## Ethics (enforced)

The evaders may target **only** Kitsune's own detector/arena + the approved public endpoints in
`harness/src/kitsune_harness/allowlist.py` (`is_allowed`). The arena gates reproduce documented open
mechanisms, vendor-neutral; there is no DoS/flood generator (the H2 DoS family is a *detection* model, not an
attack tool). See [architecture.md §13](architecture.md) — the self-contained arena *is* the ethics design.

## Deploy

The `arena` service ships in the production stack (`docker-compose.prod.yml` + the pull-based
`docker-compose.deploy.yml`); the detector relays to it via `KITSUNE_ARENA_URL=http://arena:8095`. Without
the arena container running, `/arena/*` returns 503/502. See [deploy.md](deploy.md).
