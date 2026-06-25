# harness/ — scoreboard · calibration · coordination (Python)

The blue-team measurement rig. It runs the red-team evader fleet against the detector and emits a
**dated, reproducible** scoreboard — but it also does the two things a scoreboard alone can't: prove
the rules *don't flag humans* (calibration) and catch what survives per-session detection
(coordination). Ethics are enforced in code (`allowlist.py`), not just documented.

Three pillars:

1. **Scoreboard** — score the evader fleet through the live detector; render `docs/scoreboard.md`
   + the rule × evader matrix `docs/matrix.md`.
2. **Calibration** — the trusted-but-verified precision / false-positive gate: how often each rule
   fires on a *legitimate* browser.
3. **Coordination** — cross-session fleet detection: catch a botnet that every per-session rule
   passes.

Start with [`docs/architecture.md`](../docs/architecture.md). The detector and harness never import
each other; they communicate only through the contracts in `contracts/`.

---

## 1 · Scoreboard

The artifact: a per-layer, per-evader table plus the evidence behind each verdict, stamped with the
ruleset version and date so boards stay comparable as the lab evolves.

| Module | Role |
|---|---|
| `scenarios.py` | `Scenario` protocol + `ReplayScenario` (replays a recorded session fixture — deterministic, no browser). |
| `harness.py` | `Harness.run(scenarios)` → scores each through the detector into a `Scoreboard`. |
| `scoreboard.py` | Render a `Scoreboard` to Markdown / JSON, with the evidence behind each verdict. |
| `live.py` / `liveboard.py` | Fold the verdicts real evaders read back from a *running* detector into one dated board (same renderer). |
| `corpus.py` | Score a directory of recorded `Session` JSONs in-process (the fast blue-side loop — edit a rule, re-score in <1s). |
| `report.py` | VirusTotal-style aggregator: the rule × evader coverage matrix, per-evader detection-class counts, and the *evaded* vs *unexercised* gap backlog. |
| `fleet.py` | The cross-session signature primitive (cluster by JA4 prefix) that `coordination.py` grades. |
| `models.py` | `ScenarioResult` + the dated, reproducible `Scoreboard`. |

Run the spine demo (vanilla vs a naive bot, replayed through the live detector):

```sh
uv sync
uv run python -m kitsune_harness          # markdown scoreboard
uv run python -m kitsune_harness --json    # json
```

```
| Evader    | Ver   | Network | Browser | Behavioral | Reputation | Incoh. | Score | Label |
| vanilla   | 0.1.0 | 0.00    | 0.00    | 0.00       | 0.00       | 0.00   | 0.00  | human |
| naive-bot | 0.1.0 | 0.95    | 1.00    | 0.80       | 0.50       | 0.88   | 1.00  | bot   |
```

Real evaders (camoufox, nodriver, stealth, curl-impersonate, go-tls, agent, …) implement the same
`Scenario.collect()` surface by driving a client through the edge; the harness scores them
identically. Two driver scripts wire the fleet to the live stack:

- `scripts/live_scoreboard.sh` — full sweep: brings up detector + edge + browser, runs the whole
  evader ladder, and writes `docs/scoreboard.md` + `docs/matrix.md`, refreshing `corpus/sessions/`.
- `scripts/frontier.sh` — fast frontier loop: only the evaders that still beat per-session detection
  (a Camoufox single + a Camoufox **fleet**), emitting a coordination grading snapshot
  (see `docs/coordination-proxy.md` § Worked snapshot).

---

## 2 · Calibration — the false-positive gate

The scoreboard proves rules *catch bots*; calibration proves they *don't flag humans*. A real but
unusual browser (Linux desktop, GPU-less VM, ad-blocker, no webcam) trips single-layer `environment`
tells that noisy-or accumulates into a `bot` verdict — a false positive.

`calibration.py` maps a corpus of *real* browser fingerprints → the browser-layer signals a genuine
browser would emit → a detector verdict, and reports, **per rule, how often it fired on a legitimate
browser** (any `suspicious`/`bot` is an FP). Rules over a threshold are candidates to demote to
corroborating-only / down-weight / prune — the same discipline the biomech rules got, generalised to
the fingerprint layer. The scorer is pure and source-agnostic; only rules whose every `read` is a
statically-derivable browser signal are scored (`DERIVABLE_KINDS`) — runtime-only probes (canvas /
CDP / engine / tamper) are correctly absent on a static fingerprint and marked n/a.

**The discipline: never act on a single-source FP number — corroborate across sources.**

- **Tier-1 (`browserforge_corpus.py`):** browserforge samples a Bayesian network of *real* browser
  fingerprints (the same data anti-detect tools use to look real), so it stands in for a legitimate-
  browser distribution across OS/engine — without a live device farm. This is the headline FP report
  but it is a **single generated source**.
- **Tier-2 (real captures, `corpus/calibration/`):** real browser captures, a second *independent*
  source that refutes a Tier-1 number. Three captured corpora:
  - `engines/` — headless Chromium / Firefox / WebKit (the engine families).
  - `headful/` — real headful Chrome-stable / Firefox-stock / Edge / Chromium / Firefox / WebKit,
    which surface runtime-probe tells (canvas / WebGL renderer) a static fingerprint can't carry.
  - `privacy/` — privacy browsers (Brave, Mullvad): their farbling / RFP defenses are *legitimate*,
    so they must NOT trip `canvas_lie` / `engine_stack` (engine-level farble reads as native).
  Enforced as a regression gate: `test_real_engine_captures_trip_no_spurious_coherence` fails if
  scoring these real captures starts firing any *new* convicting (`coherence`/`artifact`) rule — the
  exact precision regression the calibration exists to catch.
- **Corroborators (independent second sources):** never act on one source's FP number — each
  fingerprint/behavioral rule family has its own independent refutation source.
  - `intoli_corpus.py` — Tier-2 calibration from the Intoli user-agents dataset (real traffic, heavy
    on **real mobile**); a second source for the UA / engine-coherence rules (`task calibrate-intoli`).
  - `sapimouse_corpus.py` — second-source for the biomech power-law floor: SapiMouse (120 subjects),
    reconstructs `(x,y,t)` and runs the *shipped* biomech extractor (`task biomech-corroborate`).
  - `browserforge_corpus.py` — the Tier-1 generated source above (single-source headline FP report).
  - `berke_corpus.py` — builds the prevalence prior from the Berke et al. (PoPETs 2025) real
    consented-fingerprint corpus (aggregate-only).
  - `fpgen_coherence.py` — second-source FP-check of the font / WebGL / platform / productSub
    coherence rules vs fpgen's (Scrapfly) independently-collected data (`task fpgen-coherence`).
  - `fpgen_corroborate.py` — diffs the prevalence prior's gpu/screen/cores conditional distributions
    vs fpgen — a single-source-overfit check (`task prevalence-corroborate`).
  - `prevalence_real_corroborate.py` — Tier-3: corroborate the prevalence prior against a REAL-traffic
    fingerprint CSV and measure the rule's real-traffic FP rate (`task prevalence-real-corroborate`,
    run locally — raw data is never committed).

```sh
task calibrate                                                         # Tier-1 FP report, N=500
# or directly (browserforge is an opt-in dep, kept out of the coverage gate):
uv run --with browserforge python -m kitsune_harness.browserforge_corpus --n 400
uv run --with browserforge python -m kitsune_harness.browserforge_corpus --from-dir corpus/calibration/engines
```

### Mobile grounding

The biomech floors were grounded on desktop *mouse* motion first; the mobile *touch* surface is
grounded on its own real corpora, so the floors don't false-fire on phones:

- **BrainRun** (CC0, 646,986 real `swipe` gestures) grounds `bh.touch_uniform_velocity` and gates the
  G10 mouse-motion floors off real touch devices — a uniform-velocity swipe is the tell a humanizer
  leaves but a real thumb doesn't.
- **Aalto** grounds `bh.mobile_keystroke_interval_floor` — the minimum inter-key interval a real
  thumb-typist can hit.

Aggregate-only (percentile tables, never raw rows). See
[`docs/mobile-biomech-grounding.md`](../docs/mobile-biomech-grounding.md) and
[`docs/behavioral-data.md`](../docs/behavioral-data.md).

### Prevalence — the likelihood model

`prevalence.py` catches the gap calibration's contradiction rules leave: a fingerprint whose every
field is individually valid and mutually consistent (no contradiction) yet whose *joint combination*
is one no real user has — the BrowserForge / randomizer attack. It scores the log-prevalence of a
fingerprint's key field combo (`plat`, `gpu`, `screen`, `color`, `cores`) under a real-traffic prior;
a deep-tail score is the tell. The prior is a single source today, so this is a **corroborating**
signal (the threshold is the prior's own 1st percentile — a real fingerprint trips it ~1% of the
time). `--build-prior` writes the joint-frequency tables from N browserforge samples.

---

## 3 · Coordination — cross-session fleet detection

A single session can spoof its fingerprint perfectly (Camoufox proves it). A *fleet* cannot hide that
it shares a signature **below the spoofing layer**. `coordination.py` clusters sessions by **JA4
prefix** (JA4_a + JA4_b: the TLS engine's version/ALPN + cipher-suite identity, robust to per-launch
extension shuffling) and grades each cluster.

A shared-JA4 cluster is only a *candidate* — millions of real users run one Chrome build and share a
JA4. Grading layers on signals an anti-detect fleet can't avoid:

- **TLS-vs-JS paradox** — a genuine same-build cohort that shares a JA4 also shares its JS-visible
  identity (`hardware_concurrency`, platform, plugins). An anti-detect fleet *randomizes* those per
  instance to fake distinct users — but cannot randomize the TLS handshake.
- **Fingerprint collision** — the complement: a native anti-detect browser clones *one* high-entropy
  `fp_hash` (canvas+audio+WebGL) across the fleet. Byte-identical across *distinct* source IPs can't
  be organic (real machines each hash differently).
- **JA4_c divergence** — the cipher prefix is shared but the extensions/sig-algs vary per launch;
  since JA4 *sorts* extensions to be robust to Chrome's shuffling, a varying JA4_c is deliberate TLS
  manipulation.
- **Shared-origin WebRTC** — diverse proxy IPs fronting one WebRTC-leaked real IP.
- Corroborating-only: IP spread (residential-proxy pattern), member count, lockstep arrival timing.

**Conviction gate.** A `fleet` label (vs `candidate`) requires at least one signal a real diverse
cohort *cannot* produce — `ja4c_divergent`, a cross-IP `fp_collision`, or a `shared_real_ip`. The
JS-divergence paradox, IP spread and lockstep are corroborating only: distinct real users on one
Chrome build (Win/Mac/Linux share a JA4) legitimately differ in hardware/memory/OS and arrive from
distinct IPs — that exact shape, so it caps at `candidate` and never convicts a popular browser's user
base as a botnet. `severity` (member count + request volume + arrival rate) is operational triage,
kept distinct from the fleet *confidence* `score`.

Two modes:

- **`score_corpus` / `render_coordination`** — offline snapshot over a corpus, strongest cluster first.
- **`FleetTracker` / `render_stream`** — the online detector: ingest sessions in arrival order over a
  sliding window and alert the moment a cluster crosses the `fleet` threshold or escalates severity.

```sh
uv run python -m kitsune_harness.coordination corpus/fleet            # offline graded clusters
uv run python -m kitsune_harness.coordination --stream corpus/fleet   # online alert log
```

**Precision/recall gate (`coordination_scenarios.py`).** The coordination analog of the calibration
FP gate: legit cohorts (one popular browser build behind a corporate NAT, a campus, a CGNAT pool)
must never label `fleet`, and real fleets must. The fleet corpora that drive it, one per evasion
shape a fleet can take:

| Corpus | Fleet shape it captures |
|---|---|
| `corpus/fleet` | Camoufox fleet — shared JA4 below the spoof layer (the baseline catch). |
| `corpus/fleet-cloned` | one high-entropy `fp_hash` cloned across distinct source IPs (collision). |
| `corpus/fleet-proxy` | residential-proxy IP spread fronting a shared TLS identity. |
| `corpus/fleet-randfp-trace` | per-instance JS-fingerprint randomization over a shared handshake. |
| `corpus/fleet-replay` | replayed/lockstep arrival timing. |
| `corpus/fleet-webrtc-leak` | diverse proxy IPs fronting one WebRTC-leaked real IP (`shared_real_ip`). |

**Live mode (`live_coordination.py`).** Run the same grading against the **live** detector's session
store instead of a static corpus: it polls `/scoreboard` + `/session/{id}` over HTTP, rebuilds the
corpus, and reuses `score_corpus` / `render_coordination` — so coordination grades real egress, not
just fixtures.

```sh
task coordination-eval                                                # precision/recall over the corpora
KITSUNE_DETECTOR=http://localhost:8080 task coordination-live         # grade the live session store
```

### Behavioral biomechanics

`biomech.py` measures the structure real aimed hand motion has and Bezier "humanizers" don't — the
2/3 power law (`V ∝ R^β`, β ≈ 1/3, with R²), Fitts corrective sub-movements (speed-profile peaks),
and pause ratio. `balabit.py` loads the public Balabit Mouse-Dynamics dataset into `(x, y, t)`
trajectories so the human envelope is **calibrated against real data** instead of hand-picked
thresholds. (The raw dataset is fetched at use-time, never committed — license + size.)

---

## Ethics — enforced in code (non-negotiable)

`allowlist.py` is the hard invariant: evaders may target **only** Kitsune's own detector
(`localhost`/`127.0.0.1`/`detector`/`edge`) and a fixed allow-list of public bot/fingerprint test
endpoints. `assert_allowed(url)` raises `EthicsError` on anything else. The self-contained arena *is*
the ethics design — never a third-party or production site, and never weaken the allow-list.

---

## Verify before committing

```sh
cd harness && uv run ruff check . && uv run mypy && uv run pytest
```

Coverage gate is **≥95%** (currently **~97%**). browserforge glue (`browserforge_corpus.py`) and the
thin CLIs (`__main__.py`) are excluded from the gate — they hit external data and run via
`task calibrate`.
