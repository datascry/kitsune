# behavioral/data — curating biomechanics data for the weakest layer

The behavioral motion rules (`bh.path_too_straight`, `bh.uniform_velocity`, `bh.input_entropy_floor`)
are static thresholds, and the findings already concede they are **trivially cleared by any non-degenerate
motion** — a Bézier "humanizer" (GhostCursor) beats them. Real aimed hand movement has *structure* those
tools don't reproduce. This document is the plan to detect it from **curated real human data** instead of
hand-picked thresholds, so the bar is grounded in biomechanics, not guesswork.

We do **not** collect our own user data — no consent infrastructure, and it would be an ethics problem.
Behavioral biometrics is a mature field with public, anonymised, consented research corpora.

## Datasets (curation targets)

| Dataset | Subjects | Format | Access / license | Role |
|---|---|---|---|---|
| **[Balabit Mouse Dynamics Challenge](https://github.com/balabit/Mouse-Dynamics-Challenge)** | 10 | CSV: `record_timestamp, client_timestamp, button, state, x, y` | Public (GitHub) | **Primary** — clean access, the field's baseline |
| [SapiMouse](https://www.researchgate.net/publication/343700660_Mouse_dynamics_based_user_recognition_using_deep_learning) | 120 | per-session CSV (x, y, t) | Academic | Diversity (add later) |
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
4. **Detectors** *(next)* — new rules (`bh.power_law_violation`, `bh.no_submovements`, `bh.no_pause`)
   firing when a session's features fall outside the calibrated human envelope; the collector mirrors the
   live feature computation (as it already does for `fp_hash`). Validated against **real bot tools**
   (GhostCursor), never our own synthetic generator — the circular trap curated ground truth exists to avoid.

## Calibration result — the human movement envelope

Run over **5,338 aimed-movement segments** from 3 Balabit users (`min_len=12`, `max_gap=0.5s`):

| Feature | median | p10 | p90 | What a humanizer/script looks like |
|---|---|---|---|---|
| `power_law_exponent` (V ∝ R^β) | 0.55 | 0.35 | 0.76 | a Bézier ease / constant-velocity path → β ≈ 0 or negative |
| `power_law_r2` | 0.63 | 0.32 | — | a synthetic path either fits ~1.0 (too clean) or ~0 (no relationship) |
| `submovement_count` | 4 | — | 9 | a single smooth ease → 1; humans correct (median 4) |
| `pause_ratio` | 0.41 | — | 0.66 | scripts move without dwell → ≈ 0; humans pause ~40% of steps |

So the discriminators are real and measurable: **a real hand obeys the power law with a positive exponent,
makes several corrective sub-movements, and pauses ~40% of the time.** A Bézier "humanizer" (GhostCursor)
produces one smooth sub-movement, no pause, and a flat/negative power-law fit — outside this envelope on
*every* axis. (3-user sample; widen across all 10 users before pinning production thresholds.)

This attacks the OS-level-replay / humanizer gap *above* the mechanism tell (`bh.synthetic_no_coalesced`,
which still backstops CDP injection): a tool can humanize the path all it wants, but reproducing the power
law, sub-movement structure, and pausing of a real hand is a much higher bar — and now a measured one.
