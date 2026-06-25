# behavioral/data — curating biomechanics data for the weakest layer

The behavioral motion rules (`bh.path_too_straight`, `bh.uniform_velocity`, `bh.input_entropy_floor`)
are static thresholds, and the findings already concede they are **trivially cleared by any non-degenerate
motion** — a Bézier "humanizer" (GhostCursor) beats them. Real aimed hand movement has *structure* those
tools don't reproduce. This document is the plan to detect it from **curated real human data** instead of
hand-picked thresholds, so the bar is grounded in biomechanics, not guesswork.

We do **not** collect our own user data — no consent infrastructure, and it would be an ethics problem.
Behavioral biometrics is a mature field with public, anonymised, consented research corpora.

This page covers the **desktop mouse** layer (Balabit / SapiMouse). The **mobile touch and keystroke**
extension of the same grounding discipline — `bh.touch_uniform_velocity` and
`bh.mobile_keystroke_interval_floor`, calibrated on BrainRun / Aalto / MEU-Mobile, and the G10 gate that
keeps mouse-only floors off touch sessions — lives in
[`docs/mobile-biomech-grounding.md`](mobile-biomech-grounding.md). The same data-derived-constant principle
underlies the broader FP-rate work in [`docs/calibration.md`](calibration.md): thresholds are grounded in
real corpora, not hand-picked, and rules the data won't support are removed rather than shipped.

## Datasets (curation targets)

| Dataset | Subjects | Format | Access / license | Role |
|---|---|---|---|---|
| **[Balabit Mouse Dynamics Challenge](https://github.com/balabit/Mouse-Dynamics-Challenge)** | 10 | CSV: `record_timestamp, client_timestamp, button, state, x, y` | Public (GitHub) | **Primary** — clean access, the field's baseline |
| **[SapiMouse](https://github.com/margitantal68/sapimouse)** | 120 | `dx,dy` 128-blocks + subject label | Public (GitHub) | **Second source (sourced 2026-06-19)** — corroborates the power-law floor; `task biomech-corroborate` |
| [Bogazici Mouse Dynamics](https://www.researchgate.net/publication/351381848_Bogazici_Mouse_Dynamics_Dataset) | — | trajectory logs | Academic | Cross-validation |
| [BEACON (2026)](https://arxiv.org/pdf/2605.10867) | — | multimodal | Recent | Stretch — multimodal frontier |

**Rules of curation.** Raw data is **never committed** (size + terms): a loader fetches it at use-time, or
a tiny anonymised sample lives under a documented path. What we commit is the *pipeline* + the *calibrated
constants* it derives. Each dataset's license/attribution is respected and cited.

## What we extract — `kitsune_harness.biomech`

Pure-stdlib feature extraction over `(x, y, t)` trajectories (the same shape the collector's pointer
stream produces), grounded in the movement-science literature:

- **2/3 power law** (`power_law` → `β`, `R²`): for curved motion tangential speed scales as `V ∝ R**β`
  with `β ≈ 1/3` (Lacquaniti et al., 1983). A real hand obeys it; a Bézier ease or constant-velocity
  script does not. *(Validated by direction: an obeying trajectory fits `β > 0`, a `V ∝ R**(-1/3)` one
  `β < 0`.)*
- **Sub-movements** (`submovement_count`): Fitts's-law aimed motion = a ballistic reach + corrective
  sub-movements → several speed-profile peaks; a single Bézier ease has one.
- **Pause ratio** (`pause_ratio`): humans hesitate (near-zero-speed dwell); many scripts never pause.
- *Planned:* physiological-tremor spectrum (8–12 Hz **colored** noise vs scripted **white** jitter) — needs
  a small DFT; deferred to keep v1 dependency-free.

## Pipeline (steps 1–3 done)

1. **Feature extractor** — `biomech.py`, pure + tested. ✅
2. **Loader** — `balabit.py`: parse Balabit CSV → `(x, y, t)`, split into aimed-movement segments on
   pauses; tested on a synthetic fixture (raw data fetched at use-time, never committed). ✅
3. **Calibration** — extractor run over real Balabit movements → the human envelope (below). ✅
4. **Detectors** *(done, gated)* — `bh.power_law_violation` fires when a session's power-law exponent
   falls below the human floor. The detector's in-browser probe (`detector/demo.py`) mirrors
   `biomech.py`'s feature computation client-side (as it already does for `fp_hash`); the standalone
   `collector/` package emits only the entropy/shape features (`mouse_entropy`, `mouse_straightness`,
   `mouse_velocity_cv`, `keystroke_entropy`, `pointer_event_count`) — the biomech features ride the demo
   probe. The rule ships **`status: experimental`** (weight 0.55): the 10-user Balabit floor is a single
   research corpus, so it stays corroborating-only until corroborated against broader/Tier-3 real-device
   motion. `submovement_count` / `pause_ratio` are emitted but **ruleless** — the FP-floor is too low
   (below). Validated against **real bot tools** (the stealth humanizer), never our own synthetic generator.

## Calibration result — the human movement envelope (all 10 users)

Run over **18,537 aimed-movement segments** from **all 10** Balabit users (`min_len=12`, `max_gap=0.5s`).
The *low* percentiles matter most — they set the false-positive floor for a below-threshold rule:

| Feature | p1 | p5 | p10 | median | threshold? |
|---|---|---|---|---|---|
| `power_law_exponent` (V ∝ R^β) | **0.116** | 0.298 | 0.372 | 0.554 | **< 0.1 — safe** (FP < 1%) |
| `pause_ratio` | 0.000 | 0.062 | 0.113 | 0.393 | < 0.05 → FPs ~3–4% (short flicks) |
| `submovement_count` | 0 | 1 | 2 | 4 | < 2 → FPs ~10% (short movements) |

**The 3-user sample hid the floor; the 10-user data exposed it** — and it killed two of the three rules I
first shipped. Over a short live-capture window real humans *do* make brief, smooth, no-dwell movements:
`submovement_count` and `pause_ratio` reach down into the rule range on ~10% / ~4% of genuine segments, so
a standalone threshold there false-positives. They are **kept as observational signals** (the collector
still emits them, useful for a future composite/sequence model) but carry **no firing rule**.

Only **`power_law_exponent`** has a clean floor — human **p1 = 0.116**, comfortably above the `< 0.1`
threshold — so `bh.power_law_violation` is the one biomech rule that survives the FP-floor check: a real
hand obeys the 2/3 power law, a Bézier/constant-velocity synthetic path does not. This is the calibration
pipeline doing its job: grounding thresholds in real data and *removing* the ones the data won't support,
rather than shipping FP-prone guesses.

This attacks the OS-level-replay / humanizer gap *above* the mechanism tell (`bh.synthetic_no_coalesced`,
which still backstops CDP injection): a tool can humanize the path all it wants, but reproducing the power
law, sub-movement structure, and pausing of a real hand is a much higher bar — and now a measured one.

These desktop floors (`bh.uniform_velocity`, `bh.path_too_straight`, `bh.power_law_violation`) are
mouse-calibrated and **gated off mobile sessions (G10)** — the collector's mouse stream is `mousemove`-only,
so they never see a finger. The per-feature transferability analysis for touch (which floors survive on real
swipes, and the touch-native rule `bh.touch_uniform_velocity` it produced) is in
[`docs/mobile-biomech-grounding.md`](mobile-biomech-grounding.md).

## Second-source corroboration — SapiMouse (v0.74.25, 2026-06-19)

The standing discipline that caught the prevalence FP — *never act on a single-source floor* — was applied
to this layer too, and it surfaced two things. First, a **methodology mismatch**: the detector
(`demo.py` `powerLawExp`) fits **one β over the whole pointer stream**, but the Balabit calibration above
measured β **per pause-split segment** — different quantities, so the `p1=0.116` per-segment number never
actually bounded the rule's FP rate. Re-measuring with the *shipped* extractor exposed the real shape:

| Capture regime (Balabit, detector-style whole-stream β) | human p1 | FP @ 0.1 |
|---|---|---|
| whole session (long, many points) | 0.547 | **0.00%** |
| short ~40-sample windows (incl. dwell) | 0.115 | 0.94% aggregate, **2.88% worst individual** |

So on long/clean captures the rule is rock-solid, but on very short pause-contaminated windows the `0.1`
floor sat *at* the human p1, not above it — mild single-source over-fit.

Second, a genuine **independent corpus** was sourced to corroborate, not just re-slice Balabit:
**SapiMouse** (Antal et al., Sapientia University — 120 subjects, a different rig and era), public on
GitHub like Balabit. Its committed CSVs are model-ready fixed-length `dx,dy` blocks (no raw timestamps);
that is fine for the power law because β is the slope of `log V` on `log R` and a uniform-Δt reconstruction
only shifts the intercept, leaving β invariant. Measured with the **same `biomech.power_law` code the
detector runs** (`task biomech-corroborate`, `kitsune_harness.sapimouse_corpus`):

| SapiMouse session | subjects | samples | β p1 | β median | FP @ 0.1 | FP @ 0.05 | subjects p1 < thr |
|---|---|---|---|---|---|---|---|
| 1-min | 120 | 2,042 | 0.384 | 0.488 | 0.00% | 0.00% | 0/120 |
| 3-min | 120 | 6,359 | 0.384 | 0.485 | 0.00% | 0.00% | 0/120 |

Both sources agree: real aimed motion obeys the 2/3 power law far above the floor, independent of capture
rig. The threshold was **tightened `0.1 → 0.05`** — now justified by *two* sources (both 0% FP at 0.05) —
to add margin against the only elevated-FP regime (short Balabit windows) at **zero recall cost**: a
constant-velocity / Bezier synthetic path is β ≈ 0 (the corpus bot at β = −0.004 still fires, the lab
humanizer at β ≈ 0.45 still correctly does not), and no corpus session sits in `(0.05, 0.1)`, so labels are
unchanged. Raw SapiMouse is fetched at use-time, never committed (license + size); the committed artifact
is the pipeline + the corroborated constant. *Open frontier:* a Tier-3 real-device motion corpus (trackpad
/ touchscreen, in the wild) remains the next source — both committed corpora are mouse-on-desktop.

## Live evaluation — what the biomech rules catch, and what they don't

Run against the lab's own humanizer (`evaders/stealth` `HUMAN_MOUSE=1`: Bézier + ease-in-out + micro-jitter
+ variable timing — a GhostCursor-class mover), the captured biomech values land **inside** the human
envelope on every axis:

| Feature | human envelope | stealth humanizer |
|---|---|---|
| `submovement_count` | median 4 (p5 1) | **9** |
| `pause_ratio` | median 0.39 (p5 0.06) | **0.357** |
| `power_law_exponent` | median 0.55 (p1 0.116) | **0.448** |

A **well-crafted** humanizer reproduces real-hand biomechanics on every axis — including the power-law
exponent (0.448, well above the `< 0.1` rule), so `bh.power_law_violation` correctly does **not** fire.
That is the honest scope: the surviving biomech rule catches *constant-velocity / non-curved synthetic*
paths (β ≈ 0), not a humanizer that curves with human-like dynamics. (And the humanizer's `submovement`/
`pause` sitting squarely in the human range is the same reason those two are ruleless — short human and
humanizer movements occupy the same low values.) The well-crafted humanizer is still convicted — by the
**mechanism** tell (`bh.synthetic_no_coalesced`, the CDP-injection artifact) plus the environment floor:
the thesis holds — motion *statistics* are evadable, the *injection mechanism* and the *environment* are
not. The biomech work adds one FP-safe motion rule and a calibrated feature set, without over-claiming.
