# detector/ — the blue-team brain (Python)

The detector is a **stateless scoring facade**. It ingests `Signal` envelopes from the edge
(network) and the collector (browser/behavioral), correlates them by `session_id` into a `Session`,
runs the data-driven coherence engine, and emits an explainable `Verdict`. Persistence is the
store's job, not the detector's.

Core thesis, made mechanical here: **flag incoherence *across* layers, not just bad signals within
one.** A stripped-down headless browser is suspicious; a browser whose TLS says Chrome-on-Windows
while its JS says Safari-on-macOS is convicted. The scoring math and the conviction gate exist to
keep that distinction honest.

## The pipeline

```
signals ──▶ ingest ──▶ _with_derived ──▶ coherence engine ──▶ scoring ──▶ Verdict
 (flat)    (group by    (score-time       (rules-as-data      (noisy-or +   (explainable:
            session_id)   enrichment)       evaluator)          conviction    every point
                                                                gate)         traces to evidence)
```

1. **Ingest** (`ingest.py`) — the architectural join. A flat signal stream is grouped by
   `session_id` into `Session`s, each bucketed by layer. `merge_sessions` accumulates signals that
   arrive across multiple requests (edge posts network, collector posts browser/behavioral),
   keeping the latest signal per `kind`.
2. **Derived enrichment** (`detector._with_derived`) — score-time signals that are computed, not
   observed, and never persisted: `network.browser_absent` (a network fingerprint that loaded the
   page but ran no JS — a scripted/non-browser client), `reputation.asn_is_datacenter` /
   `reputation.is_proxy_exit` (the observed IP classified against curated CIDR lists), and
   `browser.prevalence_low` (an improbable-but-coherent fingerprint — see below). These feed the
   engine like any other tell.
3. **Coherence engine** (`coherence/`) — a generic evaluator. It knows *how* to evaluate (resolve a
   rule's `reads` against the session, run its predicate, emit a `Contradiction`); it knows nothing
   about *which* incoherences matter. That knowledge lives entirely in
   `contracts/rules/registry.yaml`.
4. **Scoring** (`scoring.py`) — turn the fired contradictions into a `score`, per-layer
   `layer_scores`, an `incoherence_score`, and a `label`.

## Scoring & the conviction gate

Scoring is a **transparent noisy-or** — `1 - ∏(1 - wᵢ)` over contradiction weights. It is monotonic
(more or stronger contradictions never lower a score) and every point traces back to its evidence.

- **Incoherence amplification.** A *cross-layer* contradiction (one touching ≥2 layers) has its
  weight amplified by `INCOHERENCE_WEIGHT` (`0.5`): a 0.6 cross-layer tell counts as 0.6·1.5 = 0.9.
  This is the mechanical expression of the thesis — incoherence across layers counts for more than a
  bad signal within one. `incoherence_score` reports the noisy-or over *only* the cross-layer
  contradictions.

- **The conviction gate** (`label_for` / `has_convicting` / `CONVICTING_CATEGORIES`). Reaching the
  `bot` threshold is not enough — a `bot` label *also* requires at least one **convicting**
  contradiction. The convicting categories are positive bot signatures:
  - `coherence` — a cross-vector contradiction (the thesis core),
  - `automation` — automation-framework surface (webdriver, CDP artifacts),
  - `artifact` — an anti-detect implementation flaw (spoofing placeholder, injected addon).

  The **corroborating** categories — `environment` (a stripped/headless capability gap),
  `behavioral`, `reputation`, `prevalence` — also fire on legitimate diversity: a desktop with no
  webcam, a quiet user, a datacenter VPN, a real-but-statistically-rare fingerprint. They can raise
  the score to `suspicious` but **never convict alone**. Without the gate, a stripped-but-real
  browser could noisy-or its way to `bot` on capability gaps it shares with stock headless — a false
  positive the gate exists to prevent. (A bare `label_for(score)` with no contradictions skips the
  gate, for threshold-only lookups.)

Thresholds (`config.py`): `score ≥ 0.65` → `bot` (gated), `≥ 0.35` → `suspicious`, else `human`.

- **The `verified` allow-list** (`scoring.verified_agent`, `Label.verified` in `models.py`). Orthogonal
  to the human↔bot axis: a *declared* automated agent that cryptographically **proved** its identity —
  a valid RFC 9421 / Web Bot Auth signature against a signer key the lab holds — is a known-good bot,
  allow-listed rather than convicted (see `net.web_bot_auth_invalid` below). The guarantee is only as
  strong as the signing key's secrecy, so the lab seeds the *public* RFC test key to demonstrate the
  bypass.

### Rule categories (`RuleCategory` in `models.py`)

| Category | Convicts? | What it means |
|---|---|---|
| `coherence` | ✅ | Cross-vector contradiction — the thesis core. |
| `automation` | ✅ | Automation-framework surface (webdriver, CDP). |
| `artifact` | ✅ | Anti-detect implementation flaw. |
| `environment` | corroborating | Capability absent (stripped/headless) — fires on stock headless too. |
| `behavioral` | corroborating | Behavioral / input signals. |
| `reputation` | corroborating | Network reputation (datacenter ASN, proxy exit). |
| `prevalence` | corroborating | Statistical improbability of a coherent fingerprint. |

### The prevalence model (`prevalence.py`)

Coherence rules catch *hard* contradictions. Prevalence catches *soft improbability* — a fingerprint
whose every field is valid and consistent (no rule fires) yet whose joint combination is one no real
user has, i.e. the randomizer attack. It scores the platform/gpu/screen/colour/cores joint as a
log-prevalence under a committed real-traffic prior (`data/prevalence_prior.json`) and, below the
prior's conservative threshold, emits `browser.prevalence_low`. It is **corroborating-only by
design**: the prior is a single source (browserforge), so rarity must not convict a real-but-rare
browser until corroborated against a second (Tier-3 real-traffic) source.

### Recent convicting rules (illustrative)

The registry head is the source of truth — these are three representative *convicting* tells that
sharpen the cross-layer thesis (full table: [`docs/detection-catalog.md`](../docs/detection-catalog.md)):

- **`br.webgl_renderer_caps_mismatch`** (G18, `coherence`) — the renderer-string-vs-GPU-capability
  tell. A source-level anti-detect fork can patch the `UNMASKED_RENDERER` string in both the main and
  Worker realms, but cannot change what the silicon can do: a string naming a recent high-end GPU
  (RTX / Radeon RX 6000+ / Apple M-series / Intel Arc) over a backend whose `MAX_TEXTURE_SIZE` is
  below the 16384 floor every such GPU exposes convicts the spoof.
- **`net.web_bot_auth_invalid`** (G25, `coherence`) — the cryptographic analog of
  `net.fake_declared_crawler`. The edge (`internal/webbotauth`) reconstructs the RFC 9421 signature
  base and verifies the Ed25519 signature; it fires **only** on a definitive forgery (a signature
  present, keyid resolving to a key the lab holds, but failing verification). An unknown keyid is
  unjudgeable and never convicts; a valid signature instead allow-lists the session as `verified`.
- **`net.tls_ext_order_static_within_session`** (N2, `coherence`) — a member of the
  within-session / temporal coherence family: a must-vary field (here the TLS extension order, which
  real clients shuffle per-connection) held static across connections within one session, or
  conversely an invariant field (JA4 / IP / h2) that rotated mid-session.

## Layout

| Module | Role |
|---|---|
| `models.py` | Pydantic models mirroring the contracts (`Signal`/`Session`/`Verdict`/`Contradiction`/`RuleCategory`/`Label`). |
| `contracts.py` | Locate + validate the JSON-Schema contracts; load the rule registry. |
| `coherence/` | `predicates.py` (fixed predicate vocabulary), `rules.py` (rules-as-data + registry loader), `engine.py` (generic evaluator). |
| `scoring.py` | Transparent noisy-or scoring; incoherence amplification + the conviction gate; `verified_agent` allow-list. |
| `applicability.py` | Pre-scoring per-browser filter: drops "expected for the identified browser" contradictions so a real browser is not convicted on a tell that is N/A for it. |
| `prevalence.py` | Log-prevalence scoring of coherent-but-improbable fingerprints (corroborating). |
| `ip_reputation.py` | Offline CIDR classification of an IP as datacenter/hosting or proxy/VPN/Tor exit. |
| `ip_reputation_refresh.py` | Deploy-time refresh of the reputation seed lists (Tor exits + cloud ranges + X4BNet VPN/datacenter) into `data/*.txt`; output not committed. |
| `reputation.py` | Offline AS-org keyword classification (the alternate, ASN-org reputation producer). |
| `geo.py` | Optional City+ASN geo enrichment for the wire panel — reads a keyless DB-IP Lite MMDB pair (`dbip-city-lite.mmdb` / `dbip-asn-lite.mmdb`, GeoLite2-name-compatible) from `KITSUNE_GEOIP_DIR`; degrades to `None` when absent. |
| `geo_refresh.py` | Deploy-time refresh of the geo/ASN MMDB pair from DB-IP Lite (keyless, CC BY 4.0) into `KITSUNE_GEOIP_DIR`; output not committed. |
| `ingest.py` | The correlation join: flat signals → `Session`s, with cross-request merge. |
| `store.py` | Schema-versioned SQLite persistence for sessions and verdicts (used by `app.py`, not by `Detector`). |
| `detector.py` | The `Detector` facade — `score` / `ingest_and_score`. Stateless. |
| `demo.py` | The in-browser demo page served to real (or evader-driven) browsers — an inline collector mirroring the TS library; posts browser+behavioral signals to `/ingest`. |
| `pages.py` | Themed HTML shell that wraps the markdown-rendered doc pages (nav + footer + per-page SEO head). |
| `styles.py` | Shared CSS foundation (design tokens + a11y rules) so `demo.py` and `pages.py` can't drift apart. |
| `app.py` | FastAPI HTTP boundary (see endpoints below). |
| `data/` | Committed seeds: prevalence prior, datacenter/proxy CIDR lists. |

### Endpoints (`app.py`)

- **API:** `POST /ingest` (correlate + score → `Verdict`s), `GET /session/{id}`, `GET /verdict/{id}`,
  `GET /scoreboard` (admin-gated), `GET /rules.json` (the live ruleset payload), `GET /healthz`.
- **Live wire view:** `GET /inspect/{session_id}` — the de-identified network/reputation view the live
  page reads, cookie-scoped to your own `ks_sid` session (geo + reputation + per-layer contradictions).
- **Served pages:** `GET /` (the demo/self-test page from `demo.py`) and the markdown-rendered doc
  pages `/detections`, `/evasions`, `/matrix`, `/how-it-works`, `/research`, with per-item drill-downs
  at `/detections/{rule_id}` and `/evasions/{slug}`.

The rules themselves live in **`../contracts/rules/registry.yaml`** — the detector treats them as
data (the active `ruleset_version` is the registry head; the full rule table is the generated
[`docs/detection-catalog.md`](../docs/detection-catalog.md)). To add or retire knowledge, edit the
registry, not the code; only a genuinely new *shape* of comparison needs a new predicate in
`predicates.py`. Retired rules are kept for history (`status: retired`) but never evaluated.

## Develop

```sh
uv sync                            # install (Python >=3.11)
uv run ruff check . && uv run ruff format --check .
uv run mypy                        # strict
uv run pytest                      # tests + coverage gate
uv run python -m kitsune_detector  # serve on :8080
```

Coverage is **tiered** (see `docs/architecture.md` §9): this package is core logic and is gated at
**≥95%** (currently ~99.8%, 200 tests). The contracts in `../contracts/` are the test oracle — every
example fixture must validate, round-trip, and score.
