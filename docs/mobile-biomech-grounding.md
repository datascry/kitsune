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

## Shipping path (remaining)
1. Collector: capture **touch/pointer swipe trajectories** on mobile (pointermove/touchmove x,y,t) — today
   `pts` is `mousemove`-only, so mobile swipes aren't measured.
2. Detector: a mobile-applicable velocity-uniformity floor at the grounded ~0.15 threshold.
3. Ground the positive with a faithful **synthetic-swipe** red-team mode (no labeled mobile-bot corpus
   exists publicly — confirmed by a 4-angle dataset search; the bot side is self-generated, as the desktop
   side did with CDP/DMTG injection).
