# Kitsune — Architecture

> Status: **living design doc** · Last revised 2026-06-19 · Owner: Kitsune
>
> This document is the contract for how Kitsune is built and the map you read first. Code may lag it;
> when they disagree, this doc is the intent and the code is the bug. Companions, all current and
> authoritative for their subsystem: [`calibration.md`](./calibration.md) (the precision gate),
> [`prevalence-model.md`](./prevalence-model.md) (the likelihood model),
> [`coordination-proxy.md`](./coordination-proxy.md) (the fleet detector),
> [`detection-catalog.md`](./detection-catalog.md) (gap analysis), [`matrix.md`](./matrix.md) (live
> rule × evader matrix), [`catalog.md`](./catalog.md) (prior art).

---

## 1. What Kitsune is

A self-contained lab that runs **both sides** of the bot-vs-human arms race against each other:

- **`detector` ("blue")** — correlates signals across four layers (network, browser fingerprint,
  behavioral, reputation) and — its differentiator — flags **incoherence *across* layers** rather than
  bad signals within one. It scores each session into an **explainable verdict** behind a precision
  discipline (the conviction gate, §7) that keeps it from flagging real-but-unusual browsers.
- **`evaders` ("red")** — a difficulty ladder of *real* anti-detect tools and browsers (vanilla,
  curl-impersonate, primp, go-tls, selenium-driverless, undetected, nodriver, zendriver, pydoll,
  camoufox, brave, stealth, h2-rapid-reset, agent) that attack the detector.
- **`harness`** — runs each evader against the detector and emits a reproducible, dated, per-layer
  **scoreboard**; it also hosts the two precision/structural subsystems that the detector cannot test
  against itself: the real-browser **calibration** gate (§9) and the **coordination/fleet** detector (§8).

Targets are exclusively Kitsune's own detector and a fixed allow-list of public test endpoints
(see [§13 Ethics](#13-ethics-as-an-invariant)). The self-contained arena *is* the ethics boundary.

---

## 2. The one idea everything hangs on: session correlation

The signals that betray a bot live at radically different altitudes:

| Layer | Lives at | Captured by |
|---|---|---|
| Network (JA3/JA4, HTTP/2, **QUIC/HTTP-3**, TCP/IP, PQ key-share, ASN) | the socket / connection | the **edge** (TLS terminator) |
| Browser fingerprint (Canvas/WebGL/Audio, webdriver, CDP, **realm coherence**) | inside the page (JS) | the **collector** |
| Behavioral (mouse/keystroke/dwell/scroll) | inside the page (JS, over time) | the **collector** |
| Reputation (IP/ASN, datacenter, proxy exit) | the source address | the **detector** (derived at score time) |

A Chrome ClientHello is not *suspicious* on its own. It becomes suspicious only when you can prove it
arrived **on the same session** as a Linux-shaped TCP stack, a `webdriver`-tampered DOM, and a
datacenter ASN. **Incoherence is a property of a correlated session, not of any single signal.**

Therefore the architectural keystone is not "a detector" — it is a **session-correlated event
pipeline**. Every layer emits `Signal`s tagged with a `session_id`; the detector joins them into a
`Session` and runs coherence rules over the joined view. Get the join right and every layer composes;
get it wrong and you have four disconnected demos.

```
                       session_id is threaded through every hop
                                        │
 evader ──▶ ┌──────────────────────┐  Set-Cookie: ks_sid   ┌───────────────────────────┐
   (red)    │  EDGE  (Go)          │  X-KS-JA4, X-KS-H2 …   │  APP  (part of detector)  │
            │  • TLS terminate     │ ─────────────────────▶ │  • serve collector.js     │
            │  • JA3 / JA4 / h2    │                        │  • POST /ingest telemetry │
            │  • QUIC / TCP-IP fp  │                        └─────────────┬─────────────┘
            │  • mint session_id   │                                      │ browser+behavioral
            │  • emit net Signals  │                                      │ Signals (POST)
            └──────────┬───────────┘                                      │
                       │ network Signals (POST /ingest)                    │
                       └───────────────────┬──────────────────────────────┘
                                           ▼
                       ┌──────────────────────────────────────────────────────┐
                       │  DETECTOR  (Python)                                    │
                       │  ingest → Session(session_id) → score-time enrich      │
                       │  (reputation · prevalence · browser_absent)            │
                       │  → COHERENCE ENGINE (rules-as-data) → SCORING          │
                       │  → noisy-or ⊕ incoherence amplification ⊕ CONVICTION   │
                       │    GATE → Verdict                                      │
                       └───────────────────────┬────────────────────────────────┘
                                               ▼
                          STORE  (SQLite, schema-versioned: sessions/signals/verdicts)
                                               ▼
       HARNESS → dated per-layer SCOREBOARD · real-browser CALIBRATION · fleet COORDINATION verdicts
```

**Correlation mechanics.** The edge is the first hop, so it mints the `session_id`, sets it as a
cookie (`ks_sid`) **and** stamps it on forwarded request headers alongside the network fingerprints
(`X-KS-JA3`, `X-KS-JA4`, `X-KS-H2`). The collector reads the cookie and tags every telemetry `Signal`
with it. Both edge and collector POST `Signal`s to the detector's `/ingest`, keyed by `session_id`.
No component shares memory or code — only the `session_id` and the contract schemas.

---

## 3. Components & language allocation

Deliberately **polyglot**, coupled **only** by HTTP + versioned JSON (the [contracts](#5-the-stable-core-contracts)).
The rule is absolute: **components communicate over the wire and never import each other's code.** Each
layer uses the ecosystem that's genuinely best for it — which also happens to mirror the learning goals.

| Component | Lang | Why this language (honestly) |
|---|---|---|
| `edge/` | **Go** | The entire TLS/h2 fingerprinting ecosystem (uTLS, fingerproxy, gospider007/fp) is Go. It's the correct tool for socket-level capture *and* the intended Go ramp. |
| `detector/` | **Python** | The blue-side brain: coherence engine, scoring, prevalence, reputation, store, HTTP app. Python's data stack is unmatched and stable. |
| `collector/` | **TypeScript** | Runs in the browser — no choice. Probes ported from CreepJS / BotD / fp-collect plus Kitsune-original realm-coherence checks. |
| `harness/` | **Python** | Orchestration, scoreboard, calibration gate, coordination scorer; shares the detector's models via the contracts. |
| `evaders/` | **Py / TS / Go** | A red-team ladder of *real* tools, each in its native language (see below) — the point is to score genuine anti-detect software, not toy clients. |

The evader fleet spans all three languages because the real tools do: Python (vanilla `httpx` control,
`primp`, `pydoll`, `undetected`, `nodriver`, `zendriver`, `selenium-driverless`, `agent`), TypeScript
(`stealth` / Camoufox-on-Playwright), and Go (`go-tls` uTLS ClientHello forging, `h2-rapid-reset`).
`camoufox` and `brave` drive real anti-detect browsers.

> **Honest tradeoff.** Polyglot costs upfront setup and a 3-toolchain CI. It's worth it here because
> the seams are natural (network capture / server scoring / in-browser collection) and forcing one
> language would put a layer in the wrong ecosystem — and would make the evader fleet fake instead of
> real. The discipline that makes it safe: the contracts are the *only* coupling, and they are versioned.

---

## 4. Data model

Four entities. These are the nouns the whole system speaks.

- **`Signal`** — one observation from one layer at one moment.
  `{ session_id, layer, kind, value, source, observed_at, schema_version }`
  e.g. `{layer: "network", kind: "ja4", value: "t13d1516h2_8daaf6152771_...", source: "edge"}`.
- **`Session`** — all signals sharing a `session_id`, grouped by layer, plus metadata
  (first/last seen, remote IP, request count). The unit coherence runs over.
- **`Contradiction`** — output of one coherence rule that fired:
  `{ rule_id, layers: [...], detail, weight, category, evidence: [signal refs] }`. The `category`
  (§6) decides whether the tell can *convict* or only *corroborate*.
- **`Verdict`** — the scored result for a session:
  `{ session_id, layer_scores: {network, browser, behavioral, reputation}, contradictions: [...],
     incoherence_score, score, label, ruleset_version, scored_at }`.
  `score ∈ [0,1]` (1 = bot); `label ∈ {human, suspicious, bot}` by configurable thresholds, with the
  `bot` label additionally **gated on a convicting signal** (§7).

Scoring is **monotonic and explainable**: the final `score` is a transparent noisy-or combination of
contradiction weights, and every point of bot-likelihood traces back to specific `Signal`s via
`Contradiction.evidence`. No black-box verdicts — that's both a learning goal and a debugging need.

---

## 5. The stable core: `contracts/`

The schemas are the actual product; everything else is swappable around them. They live in
[`contracts/`](../contracts/) as **JSON Schema (draft 2020-12)**, language-agnostic, validated in CI,
and **versioned** (`schema_version` on every envelope). Adding a field is a minor bump; changing/removing
one is a major bump and a migration. Python and TS both generate types *from* these schemas — the schema
is upstream of code in every language.

```
contracts/
  signal.schema.json          # one observation
  session.schema.json         # joined view
  verdict.schema.json         # scored result
  coherence-rule.schema.json  # the shape of a rule (rules are data — see §6)
  rules/registry.yaml         # the coherence-rule registry (ruleset_version 0.70.0)
  examples/                   # golden fixtures, validated in CI against the schemas
```

The registry carries its own `ruleset_version`, independent of the wire `schema_version`: rules churn
constantly (signals decay, gaps close), the envelopes rarely.

---

## 6. The coherence engine — rules as data

This is the differentiator and the thing that keeps Kitsune **alive in a fast-moving field**. A
coherence rule is **data, not code**: it declares which layers/signals it reads, the predicate that
detects the contradiction, a weight, and a **category**. The engine
([`coherence/engine.py`](../detector/src/kitsune_detector/coherence/engine.py)) is a small, generic
evaluator — it resolves each rule's `reads` against the session and runs its predicate; it knows nothing
about *which* incoherences matter. The knowledge lives in
[`contracts/rules/registry.yaml`](../contracts/rules/registry.yaml).

Why data-driven matters: bot-detection signals **decay**. The classic `Error.stack` CDP trick died in a
2024 V8 change. When a signal dies you set `status: retired` on the registry entry, you don't refactor
the detector. Every rule carries provenance (`added`, `last_validated`, `status`, `source`) so the
matrix can chart *signal decay over time* — an honesty mechanism, not just a writeup angle.

A rule (one of ~114 in the live registry):

```yaml
- id: net.tls_os_vs_tcp_os
  title: JA4-implied OS contradicts TCP/IP-implied OS
  layers: [network]
  reads: [network.ja4_os_hint, network.tcp_os_hint]
  predicate: not_equal           # generic predicate evaluated by the engine
  category: coherence            # convicting class — see §7
  weight: 0.6
  status: experimental           # active | experimental | retired
  added: "2026-06-17"
  last_validated: "2026-06-17"
  source: "Kitsune; cf. Vastel FP-Inconsistent (IMC 2025)"
```

Predicates (`equals`, `not_equal`, `present`, `absent`, `below_threshold`, `above_threshold`) are a
small, tested set in the engine; `not_equal` deliberately does **not** fire on missing data, so a rule
that can't resolve both sides stays silent rather than false-positive. New knowledge = a new YAML entry
+ (rarely) a new predicate, never a detector rewrite.

### The rule category taxonomy

Every rule declares a `RuleCategory` ([`models.py`](../detector/src/kitsune_detector/models.py)). The
category is the load-bearing distinction that makes the scoring honest — it separates *positive bot
signatures* from *tells that legitimate diversity also produces*:

| category | what it asserts | example | convicts? |
|---|---|---|---|
| **coherence** | a cross-vector contradiction — the thesis core | TLS says Windows, TCP says Linux | ✅ |
| **automation** | an automation-framework surface | `webdriver`, CDP `Runtime.enable`, cdc_ artifacts | ✅ |
| **artifact** | an anti-detect *implementation flaw* | a spoof failing a native-function invariant, an injected addon | ✅ |
| **environment** | a *capability gap* (stripped/headless) | no webcam, no plugins, no MIME types | ✗ corroborates |
| **behavioral** | input/timing signals | entropy below the human floor | ✗ corroborates |
| **reputation** | network reputation | datacenter ASN, proxy exit | ✗ corroborates |
| **prevalence** | statistical improbability of a *coherent* joint | a real-but-vanishingly-rare fingerprint | ✗ corroborates |

The current registry leans on coherence (the differentiator) and automation/artifact (high-precision
bot signatures), with environment/behavioral/reputation/prevalence as corroborators. The live per-rule ×
per-evader breakdown is [`matrix.md`](./matrix.md); the gap analysis driving new rules is
[`detection-catalog.md`](./detection-catalog.md).

---

## 7. Scoring and the conviction gate

Scoring ([`scoring.py`](../detector/src/kitsune_detector/scoring.py)) turns fired contradictions into a
verdict in three steps, and the third is the precision discipline that the rest of the design leans on.

1. **Noisy-or.** The score is `1 − ∏(1 − wᵢ)` over contradiction weights — monotonic (more or stronger
   contradictions never lower the score) and fully traceable to evidence.
2. **Cross-layer (incoherence) amplification.** A contradiction touching ≥2 layers has its effective
   weight boosted by `INCOHERENCE_WEIGHT` (0.5) before the noisy-or. This is the *mechanical* expression
   of the thesis: incoherence across layers counts for more than the same weight within one layer. The
   `incoherence_score` is reported separately as the thesis metric (noisy-or over only the cross-layer
   contradictions).
3. **The conviction gate.** A `bot` *label* requires both a bot-level score **and** at least one
   **convicting** contradiction — a `coherence`, `automation`, or `artifact` tell (a positive bot
   signature). The corroborating categories (`environment`, `behavioral`, `reputation`, `prevalence`)
   still raise the score and can reach `suspicious`, but **can no longer noisy-or their way to a
   conviction on their own.**

**Why the gate exists.** Without it, a real but stripped browser — a Linux desktop with no webcam, no
plugins, no PDF viewer — trips a handful of single-layer `environment` tells that noisy-or then
accumulates past the bot threshold. That is a false positive on a *real human*. The calibration gate
(§9) measured this directly: ~23% of legitimate browsers flagged, driven mostly by `media_devices_empty`
(a desktop without a webcam is not a bot). The fix is structural, not a weight tweak: the **category**,
not the weight, decides whether a tell can unlock a conviction. The score stays a full monotonic
noisy-or (every point still traces to evidence); only the *label* is gated. Re-scoring the recorded
evader sessions confirmed the gate costs no detection — real bots always trip a convicting signal.

`prevalence` is corroborating-by-design for the same reason at one remove: a single-source likelihood
prior (§8) must not convict a real-but-rare browser on rarity alone until that prior is corroborated
against a second source. The detector-side gate (`scoring.label_for`) and the coordination-side gate
(§8) are the same idea applied to the per-session and cross-session problems respectively.

Thresholds (configurable): `SUSPICIOUS_THRESHOLD = 0.35`, `BOT_THRESHOLD = 0.65`.

---

## 8. Detection families

The catalog of *what* the system looks for, by capture layer. The registry has the exact rules; this is
the map of the families and where each lives.

**Network (edge, Go).** Raw `ClientHello` → **JA3** and **JA4/JA4_a-b-c**; **HTTP/2** Akamai-style
fingerprint (SETTINGS / WINDOW_UPDATE / PRIORITY / pseudo-header order); **QUIC/HTTP-3** (decrypt the v1
Initial, extract the embedded ClientHello, derive a GREASE/PQ tell); **TCP/IP** kernel fingerprint
(p0f-style initial-TTL + option order — an OS tell *below* TLS that a UA spoof can't touch); and
**post-quantum key-share** detection (a current-Chrome handshake that omits X25519MLKEM768 is a lagging
impersonation template). These feed both single-layer rules and cross-layer coherence rules (JA4 browser
family vs UA, h2 fingerprint vs UA, TCP-implied OS vs UA).

**Browser fingerprint (collector, TS).** The largest family. Automation surface (`webdriver`, CDP
`Runtime.enable`, cdc_/Selenium/Puppeteer globals, Electron `process` leak); tamper/artifact tells
(`toString` tampering, native-function invariant violations, getter-override detection on
`webdriver`/`permissions`/`Notification`, canvas/WebGL/audio readback noise, DOMRect invariants);
engine-coherence (UA engine vs V8 stack / Math / error-message / `productSub`; UA-CH high-entropy version
and HeadlessChrome leak; `Promise.withResolvers` vs claimed Chrome version); OS-coherence (WebGL renderer
OS vs UA, font/voice OS hints, oscpu, codec support, `navigator.platform` vs UA-CH platform); and
environment tells (no plugins/MIME types/media devices, software WebGL, RFP heuristics).

**Realm coherence (collector, TS) — a Kitsune-distinct family.** Many spoofs patch only the *main JS
realm* and cannot reach a Web Worker or iframe. The collector cross-checks the main thread against a
Worker / OffscreenCanvas for **navigator** (`worker_divergence`), **timezone**
(`timezone_worker_divergence` — a process-level setting a legit CDP override *does* propagate, so it's
FP-safe and ACTIVE), **languages** (`languages_worker_divergence` — experimental: a legit CDP locale
override does *not* propagate, so it needs real-traffic FP validation), **WebGL renderer**
(`webgl_worker_divergence`), and **canvas hash** (`canvas_worker_divergence`). A geo/GPU/canvas spoof
that patches the main realm diverges from the Worker that renders clean. The whole family is closed by an
**escalation guard**: `worker_constructor_tampered` (ACTIVE) — `window.Worker`/`OffscreenCanvas` must be
native; a tool that defeats the divergence checks by wrapping the Worker constructor to inject its spoof
into worker scope cannot keep that constructor native, so the wrap itself becomes the tell.

**Behavioral (collector, TS).** Mouse/keystroke entropy, path straightness, velocity CV, coalesced-event
presence, input-before-action floors. Judged only once there is *genuine* interaction — scoring the mere
*absence* of input as bot-like is a false positive (a real visitor who hasn't moved the mouse yet), so
below an interaction floor these emit nothing and the rules resolve MISSING. Corroborating-only.

**Reputation (detector, derived at score time).** Not captured upstream — the detector classifies the
observed source IP against curated datacenter/proxy CIDR lists and emits `asn_is_datacenter` /
`is_proxy_exit`. It also emits `browser_absent` (a network fingerprint with no browser layer — loaded the
page but never ran JS) and the prevalence tell. Corroborating-only.

---

## 9. The two structural frontiers

The coherence engine catches *hard contradictions*. Two classes of bot defeat that by construction —
they produce no contradiction at all. Each gets its own principled subsystem, and each is deliberately
**corroborating-only** for the same reason: it rests on a single-source prior or on a shape that
legitimate diversity also produces.

### Frontier #1 — prevalence (likelihood) model

A fingerprint generator (BrowserForge / niespodd) samples a *real-traffic joint distribution* so that
every field is individually valid and mutually consistent — no coherence rule fires — yet the
*combination* is one no real user has. The counter is a **prevalence model**
([`prevalence.py`](../detector/src/kitsune_detector/prevalence.py),
[`prevalence-model.md`](./prevalence-model.md)): score a fingerprint's `platform`/`gpu`/`screen`/`color`/
`cores` joint against a committed real-traffic prior (`data/prevalence_prior.json`), and below the
prior's conservative p1 tail emit `browser.prevalence_low` (rule `br.fingerprint_improbable`,
experimental, weight 0.25). On a validated prototype this separated real from "scrambled" (GPU+screen
swapped) fingerprints; live, it fires on ~1% of legitimate browsers — by design, at corroborating weight.

It is `prevalence`-category specifically so it is **excluded from the convicting set**: a single-source
prior (browserforge) may reflect the generator's own sampling gaps, not true rarity, so it must not
convict a real-but-rare browser alone until corroborated against Tier-3 real traffic. This is the only
signal that scores a statistically-assembled fingerprint with no contradiction.

### Frontier #2 — coordination / fleet detector

A spoofing *fleet* defeats per-session detection: each instance is individually clean, but they share an
engine. The coordination scorer ([`coordination.py`](../harness/src/kitsune_harness/coordination.py),
[`coordination-proxy.md`](./coordination-proxy.md)) clusters sessions by **JA4 prefix** (the TLS-engine
identity below the JS spoofing layer) and grades each cluster. A shared JA4 alone is only a *candidate* —
millions of real users share a Chrome build's JA4. The discriminators are two paradoxes a fleet cannot
both avoid:

- **Randomize JS per instance** (Camoufox) → shared TLS but divergent `hardwareConcurrency`/`platform`/…
  across the cluster (the JS-divergence paradox), often with **JA4_c divergence** (per-launch
  TLS-extension randomization) and **proxy-IP spread**.
- **Clone one fingerprint profile** (BotBrowser) → JS homogeneous (reads as a real cohort) but a
  **high-entropy `fp_hash` byte-identical across distinct source IPs** — real machines each hash
  differently, so a collision is one cloned profile behind proxies.

It runs both **offline** (`score_corpus`) and **online** (`FleetTracker` — incremental clustering with
threshold/severity alerting, as a production bots/DDoS detector would). Severity (scale + arrival rate)
is reported separately from the fleet *confidence* score.

Crucially it has its **own conviction gate**, mirroring §7: a `fleet` label requires a signal a real
diverse cohort *cannot* produce — JA4_c divergence, a cloned-fingerprint collision across IPs, or a
shared WebRTC origin behind distinct proxy IPs. The JS-divergence paradox, IP spread, and lockstep timing
are corroborating only, because distinct real users on one Chrome build legitimately differ in hardware
and arrive from distinct IPs. Without the gate, a 4-user real cohort on one popular build scored `fleet`
1.00 — a botnet verdict on a browser's user base.

---

## 10. The calibration discipline — trusted but verified

The evader scoreboard proves rules *catch bots*. **Calibration** ([`calibration.py`](../harness/src/kitsune_harness/calibration.py),
[`calibration.md`](./calibration.md)) proves they *don't flag humans* — the empirical backstop for the
precision problem, and the reason the conviction gate (§7) exists.

`task calibrate` samples real browser-fingerprint *distributions* from **browserforge** (Tier-1 — a
Bayesian network of real fingerprints, the same data anti-detect tools use to look real), maps each to
the browser-layer signals a genuine browser would emit (mirroring the collector), scores them through the
detector, and reports a per-rule false-positive rate. Any `suspicious`/`bot` on a real fingerprint is a
false positive. This is the regression gate: no future rule may raise the legitimate-browser flag rate.

The discipline that makes it trustworthy is **never act on a single-source FP number.** Two checks
enforce it:

- The mapper itself is **validated against a real browser** (a live headless Chromium's actual
  fingerprint produces exactly the signals the collector emits), so measured FP rates are a property of
  the *rules*, not a broken mapping.
- A second, independent source — **Tier-2 real engines** (Chromium/Firefox/WebKit captured via
  Playwright) — is pinned in a test that fails if any rule begins firing on real Chromium or Firefox.
  This already *refuted* two browserforge FP numbers (`webgl_not_angle`, `navplatform_vs_ua` were
  browserforge data artifacts, not rule bugs) — had we trusted the single source, we'd have wrongly
  down-weighted two sound rules.

The open item is **Tier-3** (real-*desktop* traffic) for the environment-tell weights: a container is not
a desktop, so neither browserforge nor headless engines settle `media_devices_empty` and friends. This is
also the corroboration source the prevalence prior (§9) needs before its weight can rise toward convicting.

---

## 11. Testing & quality strategy

Coverage gates are **tiered** — flat 95% everywhere is a footgun on browser/network/LLM code, where
mocking to 95% buys fragile tests, not safety.

| Tier | Components | Gate | How |
|---|---|---|---|
| **Core logic** | contracts validation, detector scoring + coherence engine + conviction gate, prevalence, coordination scorer, harness aggregation, edge fingerprint parsing | **≥95% line+branch** (CI-enforced; currently ~100%) | fast unit tests, golden fixtures from `contracts/examples/`, property tests on scorers |
| **IO / integration** | edge proxy networking, collector DOM glue, evaders | **lower** + meaningful e2e | integration tests against the real spine; don't chase the number with mocks |
| **End-to-end** | full pipeline | smoke, not %-gated | docker-compose up; run an evader; assert a verdict lands with the correct `session_id` |

Principles: schemas are the test oracle (every example fixture validates and round-trips); the coherence
engine is tested rule-by-rule with crafted sessions; scorers are tested for monotonicity, the conviction
gate, and explainability (every score decomposes to its evidence); the calibration gate and the
real-engine coherence test (§10) are *enforced* regression gates, not one-time checks. Tests must be
deterministic — pinned fixtures, no live network in unit tests, frozen clocks.

Conventions are CI-enforced: a 2-line header on every script (so agents can map the repo by reading the
first two lines), Conventional Commits, and strict typing everywhere (`mypy --strict`; TS `strict` +
`noUncheckedIndexedAccess` + `exactOptionalPropertyTypes`; Go `go vet`-clean).

---

## 12. CI/CD & reproducibility

- **CI (GitHub Actions), per-language matrix:** lint + type-check + test + coverage-gate for Go,
  Python, TS independently, plus a `contracts` job validating every schema and example fixture, plus
  an e2e job (`docker compose up` + smoke) and a `task calibrate` precision gate.
- **"CD" for a lab** = build & publish container images to **GHCR** on tag, and publish the latest
  scoreboard + matrix to **GitHub Pages** (the closest thing to a live demo).
- **Reproducibility is a first-class requirement** because this field breaks you from the outside
  (browser updates, V8 changes, JA4 drift):
  - Pin everything: browser/driver/evader versions per harness run; lockfiles committed.
  - **Snapshot ground-truth** real-browser fingerprints as fixtures → detect *your own* drift and
    distinguish a real detection from a stale baseline (this is what the Tier-2 engine corpus is).
  - Every scoreboard records `ruleset_version` + evader versions + UTC date; the store is
    schema-versioned so historical comparisons stay valid as signals are added or retired.
  - Evaders (especially browser-based) are containerized so runs reproduce.

---

## 13. Ethics as an invariant

Hard rules, enforced as an allow-list in the harness (`harness/.../allowlist.py`, not just docs):

- Evaders may target **only** (a) Kitsune's own detector and (b) a fixed public set of bot-detection
  test endpoints (e.g. `bot.sannysoft.com`, CreepJS, `browserleaks.com`, `tls.peet.ws`,
  `demo.fingerprint.com`, `bot.incolumitas.com`).
- **Never** a third-party/production site; no scraping, no credentials, no live DDoS.
- The harness refuses any target not on the allow-list, and the allow-list must not be weakened. The
  self-contained arena is the ethics design.

---

## 14. Explicit non-goals (honesty about scope)

- **No real message bus / k8s / microservice theater.** HTTP + JSON + SQLite + docker-compose is the
  right amount of infrastructure for years. Versioned contracts give decoupling without the ops tax.
- **TCP/IP fingerprinting is best-effort, not a hard dependency.** It needs raw L3/L4 access
  (`CAP_NET_RAW`/`AF_PACKET`) the userspace edge doesn't always have, so the TCP-OS coherence rules are
  `experimental` until a packet-capture sidecar emits `tcp_os_hint`; the lab runs fully without it.
- **The detector does not collect.** Collection (edge, collector) and scoring (detector) stay split.
  A monolith that does both is the single biggest long-term-rot risk.
- **Not a production anti-bot product.** It's a learning + portfolio artifact; correctness,
  explainability, and reproducibility beat throughput.

---

## 15. Key risks

| Risk | Mitigation |
|---|---|
| Correlation breaks (signals don't join) | Spine-first; e2e test asserts `session_id` threads end-to-end. |
| Signal decay (V8/browser changes silently kill a check) | Rules-as-data with `last_validated`/`status`; ground-truth fixtures + the Tier-2 real-engine test detect drift. |
| **Precision (real browsers flagged as bots)** | The conviction gate (§7) + the calibration regression gate (§10); environment/behavioral/reputation/prevalence corroborate but never convict. |
| Single-source FP/prior over-leverage | Never act on one source: mapper validated against a real browser, rules cross-checked against Tier-2 engines, prevalence/coordination gated to corroborating until Tier-3. |
| Behavioral layer over-scoped / false-positive on quiet users | Corroborating-only; floors judged only above a genuine-interaction threshold, else emit nothing. |
| Polyglot sprawl | Contracts are the only coupling; one Taskfile; CI enforces each toolchain. |
| Data-leakage in detector eval | Don't validate the detector solely against the same generator (browserforge) the stealth evader uses; that is exactly why Tier-2/Tier-3 sources exist. |
```
