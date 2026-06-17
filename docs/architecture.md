# Kitsune — Architecture

> Status: **living design doc** · Last revised 2026-06-17 · Owner: Kitsune
>
> This document is the contract for how Kitsune is built. Code may lag it; when they disagree,
> this doc is the intent and the code is the bug. Companion: [`catalog.md`](./catalog.md) (prior art).

---

## 1. What Kitsune is

A self-contained lab that runs **both sides** of the bot-vs-human arms race against each other:

- **`detector` ("blue")** — scores bot-likelihood across four layers (network, browser fingerprint,
  behavioral, reputation) and — its differentiator — flags **incoherence *across* layers**.
- **`evaders` ("red")** — a difficulty ladder of clients (`vanilla → stealth → agent → go-tls`) that
  attack the detector.
- **`harness`** — runs each evader against the detector and emits a reproducible, dated, per-layer
  **scoreboard** showing the arms race over time.

Targets are exclusively Kitsune's own detector and a fixed allow-list of public test endpoints
(see [§11 Ethics](#11-ethics-as-an-invariant)). The self-contained arena *is* the ethics boundary.

---

## 2. The one idea everything hangs on: session correlation

The signals that betray a bot live at radically different altitudes:

| Layer | Lives at | Captured by |
|---|---|---|
| Network (JA3/JA4, HTTP/2, TCP/IP, ASN) | the socket / connection | the **edge** (TLS terminator) |
| Browser fingerprint (Canvas/WebGL/Audio, webdriver, CDP) | inside the page (JS) | the **collector** |
| Behavioral (mouse/keystroke/dwell/scroll) | inside the page (JS, over time) | the **collector** |
| Reputation (request-graph, IP/ASN, PoW) | across many requests | the **detector** |

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
            │  • mint session_id   │                        └─────────────┬─────────────┘
            │  • emit net Signals  │                                      │ browser+behavioral
            └──────────┬───────────┘                                      │ Signals (POST)
                       │ network Signals (POST /ingest)                    │
                       └───────────────────┬──────────────────────────────┘
                                           ▼
                       ┌──────────────────────────────────────────────────────┐
                       │  DETECTOR  (Python)                                    │
                       │  ingest → Session(session_id) → per-layer scorers      │
                       │  → COHERENCE ENGINE (rules-as-data) → Verdict          │
                       └───────────────────────┬────────────────────────────────┘
                                               ▼
                          STORE  (SQLite, schema-versioned: sessions/signals/verdicts)
                                               ▼
                          HARNESS → dated per-layer SCOREBOARD (md / json / html)
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
| `detector/` | **Python** | The blue-side brain: coherence rules, behavioral ML classifiers, graph/reputation analysis, scoring. Python's data/ML stack is unmatched and stable. |
| `collector/` | **TypeScript** | Runs in the browser — no choice. Signals ported from CreepJS / BotD / fp-collect. |
| `harness/` | **Python** | Orchestration + analysis + report generation; shares models with the detector via the contracts. |
| `evaders/stealth/` | **TypeScript** | Camoufox/Playwright (ESM). Same language as the collector. |
| `evaders/agent/` | **Python** | browser-use / Claude Computer Use are Python. |
| `evaders/go-tls/` | **Go** | uTLS ClientHello forging. |
| `evaders/vanilla/` | **Python** | Trivial baseline client (httpx); the control. |

> **Honest tradeoff.** Polyglot costs upfront setup and a 3-toolchain CI. It's worth it here because
> the seams are natural (network capture / server scoring / in-browser collection) and forcing one
> language would put a layer in the wrong ecosystem. The discipline that makes it safe: the contracts
> are the *only* coupling, and they are versioned.

---

## 4. Data model

Four entities. These are the nouns the whole system speaks.

- **`Signal`** — one observation from one layer at one moment.
  `{ session_id, layer, kind, value, source, observed_at, schema_version }`
  e.g. `{layer: "network", kind: "ja4", value: "t13d1516h2_8daaf6152771_...", source: "edge"}`.
- **`Session`** — all signals sharing a `session_id`, grouped by layer, plus metadata
  (first/last seen, remote IP, request count). The unit coherence runs over.
- **`Contradiction`** — output of one coherence rule that fired:
  `{ rule_id, layers: [...], detail, weight, evidence: [signal refs] }`.
- **`Verdict`** — the scored result for a session:
  `{ session_id, layer_scores: {network, browser, behavioral, reputation}, contradictions: [...],
     incoherence_score, score, label, ruleset_version, scored_at }`.
  `score ∈ [0,1]` (1 = bot); `label ∈ {human, suspicious, bot}` by configurable thresholds.

Scoring is **monotonic and explainable**: the final `score` is a transparent combination of per-layer
scores and the incoherence score, and every point of bot-likelihood traces back to specific `Signal`s
via `Contradiction.evidence`. No black-box verdicts — that's both a learning goal and a debugging need.

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
  rules/registry.yaml         # the initial coherence-rule registry
  examples/                   # golden fixtures, validated in CI against the schemas
```

---

## 6. The coherence engine — rules as data

This is the differentiator and the thing that keeps Kitsune **alive in a fast-moving field**. A
coherence rule is **data, not code**: it declares which layers/signals it reads, the contradiction it
detects, and a weight. The engine is a small, generic evaluator; the *knowledge* is in the registry.

Why data-driven matters: bot-detection signals **decay**. The classic `Error.stack` CDP trick died in a
2024 V8 change (see catalog §4). When a signal dies you **retire a registry entry**, you don't refactor
the detector. Every rule carries provenance (`added`, `last_validated`, `status`, `source`) so the
scoreboard can literally chart *signal decay over time* — a great writeup angle and an honesty mechanism.

A rule (see `contracts/rules/registry.yaml` for the live set):

```yaml
- id: net.tls_os_vs_tcp_os
  title: TLS-implied OS contradicts TCP/IP-implied OS
  layers: [network]
  reads: [network.ja4_os_hint, network.tcp_os_hint]
  predicate: not_equal           # generic predicate evaluated by the engine
  weight: 0.6
  status: active                 # active | experimental | retired
  added: 2026-06-17
  last_validated: 2026-06-17
  source: "Kitsune; cf. Vastel FP-Inconsistent (IMC 2025)"
```

Initial registry (10 rules) spans the cross-layer seams that matter most:

| id | contradiction | layers | weight |
|---|---|---|---|
| `net.tls_os_vs_tcp_os` | JA4-implied OS ≠ TCP/IP-implied OS | network | 0.6 |
| `net.tls_vs_ua_browser` | JA4 browser family ≠ User-Agent browser | network↔browser | 0.7 |
| `net.h2_vs_ua_browser` | HTTP/2 fingerprint ≠ UA browser | network↔browser | 0.6 |
| `br.ua_platform_vs_ch_platform` | `navigator.platform`/UA ≠ `Sec-CH-UA-Platform` | browser | 0.7 |
| `br.webdriver_present` | `navigator.webdriver === true` | browser | 0.9 |
| `br.cdp_runtime_enabled` | CDP `Runtime.enable` detected (Proxy ownKeys trap) | browser | 0.85 |
| `br.canvas_lie` | Canvas/WebGL API tampering (getter override) detected | browser | 0.7 |
| `bh.input_entropy_floor` | mouse/keystroke timing below human entropy floor | behavioral | 0.6 |
| `bh.no_input_before_action` | form submit / nav with zero pointer or key events | behavioral | 0.5 |
| `rep.datacenter_asn_residential_ua` | datacenter ASN presenting as consumer browser | reputation↔network | 0.5 |

Predicates (`not_equal`, `equals`, `present`, `below_threshold`, `absent`) are a small, tested,
extensible set in the engine; rules reference them by name. New knowledge = a new YAML entry + (rarely)
a new predicate, never a detector rewrite.

---

## 7. Repository layout

Monorepo — the whole point is running red against blue and comparing them, so they live together.

```
kitsune/
├── contracts/         # JSON Schemas + rule registry (the stable core)
├── edge/              # Go: TLS/JA4/h2 capture proxy + session correlation
├── collector/         # TS: in-browser fingerprint + behavioral telemetry
├── detector/          # Python: ingest, scoring, coherence engine, store
├── harness/           # Python: orchestration + scoreboard generation
├── evaders/
│   ├── vanilla/       # Python: baseline httpx client (the control)
│   ├── stealth/       # TS: Camoufox/Playwright
│   ├── agent/         # Python: browser-use / Claude Computer Use
│   └── go-tls/        # Go: uTLS ClientHello forging
├── docs/              # architecture.md, catalog.md, writeups
├── scripts/           # dev helpers
├── Taskfile.yml       # one task runner across the polyglot repo
├── .pre-commit-config.yaml
└── .github/workflows/ # per-language CI matrix + Pages publish
```

---

## 8. Build phasing — spine first

Even though we're not bound to the original MVP plan, the *order* still matters: build a **thin
vertical slice through every layer before deepening any one**, because that's what de-risks the
correlation keystone.

1. **The spine** *(current phase).* `contracts` + edge (JA4 capture + session cookie) + collector
   (one FP signal) + detector (join + store + a handful of coherence rules) + harness/scoreboard.
   Gate: a single `session_id` provably threads socket → browser → verdict, vanilla scores lower than
   a trivially-bad client.
2. **Deepen signals + the coherence registry** — the differentiator grows here.
3. **Evader ladder** — vanilla → stealth → go-tls → agent, all scored on the same board.
4. **Behavioral ML + reputation** — hardest, least open tooling; its own phase, never a spine blocker.
5. **Harden + writeup + open-source.**

---

## 9. Testing & quality strategy

Coverage gates are **tiered** — flat 95% everywhere is a footgun on browser/network/LLM code, where
mocking to 95% buys fragile tests, not safety.

| Tier | Components | Gate | How |
|---|---|---|---|
| **Core logic** | contracts validation, detector scoring + coherence engine, harness aggregation, edge fingerprint parsing | **≥95% line+branch** (CI-enforced, build fails under) | fast unit tests, golden fixtures from `contracts/examples/`, property tests on scorers |
| **IO / integration** | edge proxy networking, collector DOM glue, stealth/agent evaders | **~60–70%** + meaningful e2e | integration tests against the real spine; don't chase the number with mocks |
| **End-to-end** | full pipeline | smoke, not %-gated | docker-compose up; run vanilla evader; assert a verdict lands with the correct `session_id` |

Principles: schemas are the test oracle (every example fixture validates and round-trips); the
coherence engine is tested rule-by-rule with crafted sessions; scorers are tested for monotonicity and
explainability (every score decomposes to its evidence). Tests must be deterministic — pinned fixtures,
no live network in unit tests, frozen clocks.

---

## 10. CI/CD & reproducibility

- **CI (GitHub Actions), per-language matrix:** lint + type-check + test + coverage-gate for Go,
  Python, TS independently, plus a `contracts` job validating every schema and example fixture, plus
  an e2e job (`docker compose up` + vanilla smoke).
- **"CD" for a lab** = build & publish container images to **GHCR** on tag, and publish the latest
  scoreboard to **GitHub Pages** (the closest thing to a live demo).
- **Reproducibility is a first-class requirement** because this field breaks you from the outside
  (browser updates, V8 changes, JA4 drift):
  - Pin everything: browser/driver/evader versions per harness run; lockfiles committed.
  - **Snapshot ground-truth** real-browser fingerprints as fixtures → detect *your own* drift and
    distinguish a real detection from a stale baseline.
  - Every scoreboard records `ruleset_version` + evader versions + UTC date; the store is
    schema-versioned so historical comparisons stay valid as signals are added or retired.
  - Evaders (especially browser-based) are containerized so runs reproduce.

---

## 11. Ethics as an invariant

Hard rules, enforced as an allow-list in the harness config (not just docs):

- Evaders may target **only** (a) Kitsune's own detector and (b) this fixed public set:
  `bot.sannysoft.com`, `abrahamjuliot.github.io/creepjs`, `browserleaks.com`, `tls.peet.ws`,
  `demo.fingerprint.com`, `bot.incolumitas.com`.
- **Never** a third-party/production site; no scraping, no credentials, no live DDoS.
- The harness refuses any target not on the allow-list. The self-contained arena is the ethics design.

---

## 12. Explicit non-goals (honesty about scope)

- **No real message bus / k8s / microservice theater.** HTTP + JSON + SQLite + docker-compose is the
  right amount of infrastructure for years. Versioned contracts give decoupling without the ops tax.
- **TCP/IP fingerprinting is an optional sensor, not core.** It needs raw L3/L4 access that fights a
  clean app-layer proxy (high effort, low portability). Wired as an opt-in side input; the lab runs
  fully without it.
- **The detector does not collect.** Collection (edge, collector) and scoring (detector) stay split.
  A monolith that does both is the single biggest long-term-rot risk.
- **Not a production anti-bot product.** It's a learning + portfolio artifact; correctness,
  explainability, and reproducibility beat throughput.

---

## 13. Key risks

| Risk | Mitigation |
|---|---|
| Correlation breaks (signals don't join) | Spine-first; e2e test asserts `session_id` threads end-to-end before any layer is deepened. |
| Signal decay (V8/browser changes silently kill a check) | Rules-as-data with `last_validated`/`status`; ground-truth fixtures detect drift. |
| Behavioral layer over-scoped | Its own phase (4), never a spine dependency; start with entropy floors before ML. |
| Polyglot sprawl | Contracts are the only coupling; one Taskfile; CI enforces each toolchain. |
| Data-leakage in detector eval | Don't train/validate the detector solely against the same generator (apify/browserforge) the stealth evader uses. |
