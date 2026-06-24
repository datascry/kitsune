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

## Full feature sweep (161,845 human swipes)

Every desktop biomech extractor, measured on real human swipes, to decide convicting vs informational:

| feature | human distribution | desktop floor | transfers as a *convicting* tell? |
|---|---|---|---|
| **velocity CV** | p1 0.235 · median 0.602 | `< 0.08` | **YES** → shipped `bh.touch_uniform_velocity` at 0.15 (below human p1) |
| **straightness** | p25 0.981 · median 0.993 | `> 0.97` | **NO** — would FP on >50% (swipes are near-straight) |
| **power-law β** | fits 98.4% of swipes; p25 **−0.014** · median 0.16 | `< 0.05` | **NO** — the human β distribution overlaps the bot region; the desktop floor would FP on ~30% of real swipes |
| **sub-movements** | 0→**15%** · 1→63% · 2→14% · 3+→7% | n/a | **NO** — 15% of human swipes have 0 peaks, so the "0 = constant replay" tell FPs on 1-in-7 humans |
| duration / points | median 135 ms / 7 pts | — | informational only |

So **only velocity-CV transfers as an FP-safe convicting tell on touch.** The others are displayed as
**informational** panel rows (measured value, no human/bot verdict) for transparency — never as detectors.

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

## Mobile KEYSTROKE biomech (grounded on MEU-Mobile KSD)

The keystroke floors are device-agnostic, so G10 kept them active on mobile — but they were *desktop*-
calibrated. Validated on **MEU-Mobile KSD** (UCI 399, **CC BY 4.0**) — 2,856 real mobile keystroke records,
56 subjects (Nexus 7, password `tie5Roanl`). Down-down latency = inter-key interval; entropy via the same
log-bucket Shannon the collector uses.

| floor | fires below | human mobile p1 | margin |
|---|---|---|---|
| **inter-key interval** (`bh.keystroke_interval_floor`, G13) | 30 ms | per-record median **216 ms** | ~7× |
| **keystroke entropy** (`bh.keystroke_entropy_floor`) | 0.15 | **0.625** | ~4× |

Both floors are **FP-safe on mobile with a large margin** — mobile typing is far slower and higher-entropy
than the floors require (median inter-key 504 ms; entropy 0.89). No recalibration needed; the floors are
now *grounded* on mobile, not assumed. Gesture/glide typing fires few `keydown`s (below the ≥4 gate, not
judged) and autocomplete inserts whole words as single events (no rapid keydown burst), so neither FPs.

Reference distributions (MEU-Mobile): key **hold/dwell** median 88 ms (a candidate future feature — needs
`keyup` capture, not collected today); **pressure** median 0.14 (varies, but `KeyboardEvent` exposes no
pressure in-browser — touch-only). The inter-key-interval row is now shown in the panel.

**Mobile-aware interval floor — SHIPPED (grounded on Aalto ITE free-text).** Validated on **Aalto ITE
Typing** (Zenodo 12528163, **CC BY 4.0**) — **42.3M keystrokes across 849,909 real free-text mobile typing
sessions** (own phones). Per-session median inter-key: p1 **118 ms**, median 202 ms. The fraction of real
human sessions whose median falls below a candidate floor:

| floor | human sessions FP'd |
|---|---|
| 30 ms (universal) | 0.003% |
| 50 ms | 0.007% |
| **80 ms (mobile floor)** | **0.018%** |
| 120 ms | 1.215% (too high) |

Shipped **`bh.mobile_keystroke_interval_floor`** (< 80 ms, mobile-gated): a mobile session typing 30–80 ms/key
is non-human (faster than 99.98% of real mobile typists) but evades the universal 30 ms floor. 80 ms, not
120 ms, because the FP rate jumps 70× between them. The collector emits `mobile_keystroke_interval_ms` only
on a mobile session, so it never touches desktop typists (who legitimately type faster). Entropy floor (0.15)
re-confirmed FP-safe on free text too (per-session entropy p1 0.699). Hold/dwell + flight time remain
ungroundable from the processed log (one timestamp per press; the raw set with key-up is 65 GB).

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
