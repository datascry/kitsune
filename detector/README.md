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

## Layout

| Module | Role |
|---|---|
| `models.py` | Pydantic models mirroring the contracts (`Signal`/`Session`/`Verdict`/`Contradiction`/`RuleCategory`/`Label`). |
| `contracts.py` | Locate + validate the JSON-Schema contracts; load the rule registry. |
| `coherence/` | `predicates.py` (fixed predicate vocabulary), `rules.py` (rules-as-data + registry loader), `engine.py` (generic evaluator). |
| `scoring.py` | Transparent noisy-or scoring; incoherence amplification + the conviction gate. |
| `prevalence.py` | Log-prevalence scoring of coherent-but-improbable fingerprints (corroborating). |
| `ip_reputation.py` | Offline CIDR classification of an IP as datacenter/hosting or proxy/VPN/Tor exit. |
| `reputation.py` | Offline AS-org keyword classification (the alternate, ASN-org reputation producer). |
| `ingest.py` | The correlation join: flat signals → `Session`s, with cross-request merge. |
| `store.py` | Schema-versioned SQLite persistence for sessions and verdicts (used by `app.py`, not by `Detector`). |
| `detector.py` | The `Detector` facade — `score` / `ingest_and_score`. Stateless. |
| `app.py` | FastAPI HTTP boundary: `/ingest`, `/session/{id}`, `/verdict/{id}`, `/scoreboard`, `/healthz`, `/`. |
| `data/` | Committed seeds: prevalence prior, datacenter/proxy CIDR lists. |

The rules themselves live in **`../contracts/rules/registry.yaml`** (currently `ruleset_version:
0.70.0`) — the detector treats them as data. To add or retire knowledge, edit the registry, not the
code; only a genuinely new *shape* of comparison needs a new predicate in `predicates.py`. Retired
rules are kept for history (`status: retired`) but never evaluated.

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
