# Mobile touch-biomech grounding (BrainRun, CC0)

Grounding aggregate for extending the desktop mouse-biomech floors to **mobile touch swipes** (radar
**X6** / **G10**). De-identified: percentile tables only, never raw rows.

## Source
**BrainRun** — Tzafilkou & Protogeros, Zenodo `10.5281/zenodo.2598135`, **CC0 1.0 (public domain)**.
3.11M gestures, 2,418 devices. We analysed the **646,986 `swipe` gestures**, capped at 200/device to avoid
per-user skew → **161,780 swipes across 2,117 devices**. Per-swipe features computed from the point stream
(`moveX/moveY` position, `vx/vy` velocity): velocity coefficient-of-variation (speed std/mean) and
straightness (net displacement / path length).

## Human-swipe distribution

| percentile | 1 | 5 | 25 | 50 | 75 | 95 | 99 |
|---|---|---|---|---|---|---|---|
| **velocity CV** (low = too-uniform = bot) | 0.235 | 0.368 | 0.512 | 0.602 | 0.736 | 1.078 | 1.64 |
| **straightness** (high = too-straight = bot; 1.0 = perfect line) | 0.265 | 0.868 | 0.982 | 0.993 | 0.997 | 1.0 | 1.0 |
| points/swipe | 5 | 5 | 6 | 7 | 9 | 24 | 65 |
| duration (ms) | 69 | 83 | 105 | 135 | 184 | 515 | 1506 |

## Per-feature transferability verdict

- **`bh.path_too_straight` — NOT transferable to touch.** Human swipes are inherently near-straight
  (median 0.993; >50% exceed any sane high-straightness threshold; p25 already 0.982). The desktop rule
  would false-fire on the majority of real swipes, and no touch threshold separates human from bot (both
  swipe straight). **Stays in `_MOBILE_BIOMECH_NA`.** This is the empirical proof behind G10's gate.
- **`bh.uniform_velocity` — TRANSFERABLE.** Human swipe velocity-CV has p1 = **0.235**, far above the
  desktop floor (0.08). The floor is FP-safe on touch *and* has headroom: a touch-calibrated threshold of
  **~0.15** (≈36% below the human 1st percentile) catches too-uniform synthetic swipes while staying
  zero-FP on the 161,780-swipe human baseline. Candidate to re-enable on mobile with a mobile threshold.
- **`power_law_violation` / `synthetic_no_coalesced` / `input_entropy_floor`** — not yet touch-grounded
  (power-law needs the SapiMouse-style fit on BrainRun; coalesced is a desktop pointer-API structure).
  Stay gated until grounded.

## Shipping path — SHIPPED
1. ✅ Collector: captures **touch-swipe trajectories** via `touchstart`/`touchmove`/`touchend` (touch events,
   not pointer events — pointer events coalesce moves and drop `pointerup` for synthetic/replayed touch),
   computes per-swipe velocity-CV (≥5 points), emits the **median per-swipe** `behavioral.touch_velocity_cv`.
   In demo.py (authoritative) + livepage probes.ts.
2. ✅ Detector: **`bh.touch_uniform_velocity`** (below_threshold 0.15, behavioral/corroborating, experimental).
3. ✅ Grounded end-to-end: a constant-velocity replay swipe (CV ≈ 0.005, via rAF) **fires** the rule through
   the real detector; a varied/natural swipe (CV ≈ 0.24–0.6) stays **silent** (FP-safe). Engine test pins
   the firing. Notable: a *naive* CDP swipe-injection is jittery (CV ≈ 0.24, ≈ the human p1) and correctly
   does NOT fire — only a deliberately constant-velocity replay does, which is the intended target.
