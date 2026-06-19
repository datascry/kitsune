# calibration — measuring false positives on real browsers

The evader scoreboard proves rules *catch bots*. This proves they *don't flag humans*. It is the
empirical backstop for the precision problem: a real but unusual browser (desktop with no webcam, a
non-Retina Mac, a VM, an ad-blocker) trips single-layer `environment` tells that noisy-or then
accumulates into a `bot` verdict — a false positive. Same discipline the biomech rules got from the
Balabit calibration, now generalised to the fingerprint layer.

## How it works

```sh
task calibrate            # or: uv run --with browserforge python -m kitsune_harness.browserforge_corpus --n 500
```

[browserforge](https://github.com/daijro/browserforge) samples from a Bayesian network of **real**
browser fingerprints (the same data anti-detect tools use to look real) — a stand-in for legitimate
browser distributions across OS/engine, without a live device farm.
[`harness/calibration.py`](../harness/src/kitsune_harness/calibration.py) maps each fingerprint to the
browser-layer signals a genuine browser would emit (mirroring the collector), scores it through the
detector, and reports, per rule, how often it fired on a legitimate browser. **Any `suspicious`/`bot`
on a real fingerprint is a false positive.** Runtime-only probes (canvas/CDP/engine/tamper) aren't
derivable from a static fingerprint, so ~38 rules are "not calibrated" here — but those are the
high-precision tells that don't false-positive anyway; the **30 calibrated rules are the FP-prone
environment + fingerprint-coherence ones**, exactly the surface that matters.

## First run (500 fingerprints, ruleset v0.57.0) — the precision problem, quantified

**Verdict distribution: human 77% · suspicious 15% · bot 8%** → **23% of legitimate browsers flagged.**

| Rule | category | weight | FP rate | why a real browser trips it |
|---|---|---|---|---|
| `br.media_devices_empty` | environment | 0.55 | **18.2%** | a real desktop with no webcam/mic has empty `enumerateDevices` |
| `br.macos_dpr1` | environment | 0.30 | **5.2%** | real non-Retina Intel Macs report `devicePixelRatio = 1` |
| `br.mimetypes_empty` | environment | 0.50 | **4.4%** | modern browsers expose no MIME types |
| `br.no_plugins` | environment | 0.40 | **4.4%** | modern browsers expose no plugins |
| `br.no_pdfviewer` | environment | 0.50 | **4.2%** | some real browsers report `pdfViewerEnabled = false` |
| `br.navplatform_vs_ua` | coherence | 0.70 | **3.6%** | real `navigator.platform` vs UA-platform mismatches (e.g. mobile) |
| `br.webgl_not_angle` | coherence | 0.55 | **3.2%** | some real Chrome renderers aren't ANGLE-wrapped (shipped experimental for this reason) |

## What it tells us

`media_devices_empty` alone causes most of the false positives — a desktop without a webcam is not a
bot. These single-layer `environment` tells are **not bot-specific**; they fire on legitimate diversity,
and noisy-or amplifies a handful of them into a conviction. The fix is the scoring change (gate `bot` on
a convicting coherence/automation/artifact signal; cap the environment contribution) plus down-weighting
or pruning the offenders above — and then this calibration becomes a **regression gate**: no future rule
(including anything the enumeration fleet surfaces) may push the legitimate-browser flag rate back up.

## The convicting-signal gate (shipped v0.64.0)

The scoring change above is now implemented: a `bot` *label* requires at least one **convicting**
contradiction — `coherence`, `automation`, or `artifact` (a positive bot signature). The corroborating
categories — `environment` (a stripped/headless capability gap), `behavioral`, `reputation` — still
raise the score and can reach `suspicious`, but can no longer noisy-or their way to a conviction on their
own. The score itself stays a full, monotonic noisy-or (every point still traces to evidence); only the
label is gated (`detector/scoring.py:label_for`).

Measured on **one** 800-fingerprint corpus scored both ways (same fingerprints — the only honest
before/after, since each `task calibrate` run samples fresh):

| labeler | bot | suspicious | human |
|---|---|---|---|
| bare threshold (old) | 62 | 127 | 611 |
| **convicting-gate (new)** | **43** | 146 | 611 |

**19 environment-only `bot` false positives → `suspicious` (−31% hard bot FPs), human rate unchanged, and
zero evader regression** — re-scoring all 31 recorded evader sessions, every one still scores `bot` and
every one carries a convicting signal (bots always trip one). The residual 43 bot FPs are driven by the
two browserforge coherence *data artifacts* (`navplatform_vs_ua`, `webgl_not_angle`) the Tier-2 engines
already refuted — not a scoring problem, so the gate has removed every env-only bot FP that scoring *can*
fix. The remaining lever is the Tier-3 real-desktop source for the environment-tell weights themselves.

## Methodology validation (not just browserforge)

browserforge is one generated distribution, not ground truth — so the mapper itself is validated against a
**real browser**: a live headless Chromium's actual fingerprint, run through `signals_from_fingerprint`,
produces exactly the signals the real `demo.py` collector emits for that browser — the container's
environment tells (`webgl_software`, `media_devices_empty`, `mimetypes_empty`, `no_plugins`,
`no_pdfviewer`), `ch_he_headless`, `webdriver_present`, and **zero spurious coherence** (webgl-OS /
platform / CH-version all agree). So the FP rates measured here are a property of the *rules*, not of a
broken fingerprint→signal mapping. ## Second data source (Tier-2 real engines) — and what it refuted

`task calibrate` defaults to browserforge (Tier-1). A second, independent source lives in
`corpus/calibration/engines/` — **real** Chromium/Firefox/WebKit fingerprints captured via Playwright —
scored with `--from-dir`:

```sh
uv run python -m kitsune_harness.browserforge_corpus --from-dir ../corpus/calibration/engines
```

These engines are headless/automated (they correctly score `bot` — `webdriver_present`/`ch_he_headless`),
so they are **not** a legitimate-FP source; their value is **coherence-rule portability**: do the
coherence rules browserforge flagged as FP-prone fire on a *real* engine? The answer refuted two
browserforge numbers:

| rule | browserforge (Tier-1) FP | real engines (Tier-2) | verdict |
|---|---|---|---|
| `br.webgl_not_angle` | 3.2% | fires on **none** | **browserforge data artifact** — its renderer distribution includes non-ANGLE strings under Chrome UAs; real Chromium always ANGLE-wraps |
| `br.navplatform_vs_ua` | 3.6% | only on WebKit (Mac UA + Linux container platform) | **artifact** — real Chromium/Firefox are coherent; the WebKit fire is a Playwright-on-Linux quirk, not real Safari |

**Had we trusted the single source, we'd have wrongly down-weighted two sound rules.** This is the
over-leverage guard working: never prune/down-weight on a single-source FP number. The environment-tell
FP rates (media_devices_empty etc.) still need a Tier-3 real-*desktop* source — a container is not a
desktop, so neither browserforge nor headless engines settle those.

**The guard is now an enforced gate, not a one-time check.** `test_real_engine_captures_trip_no_spurious_coherence`
scores the three real-engine captures through the detector and pins the convicting (coherence/artifact)
rules each may fire: **none** for Chromium and Firefox (a real engine is internally coherent), and only
`br.navplatform_vs_ua` for WebKit — itself a property of the *capture*, not a rule bug, since Playwright's
WebKit on Linux serves a macOS Safari UA while `navigator.platform` leaks `Linux x86_64` (a real Safari on
a real Mac would never produce that contradiction). Any future rule that begins firing on real Chromium or
Firefox breaks the test — an FP on a real browser caught against the second source, before it can ship.
(Headful captures via Playwright + xvfb were attempted as a cleaner Tier-2 source but the browsers hang on
headful launch in this headless/no-GPU sandbox; the headless engine captures remain the achievable second
source here.)

## Honest scope

browserforge lacks a few signals (speech-synthesis voices, `getHighEntropyValues` runtime, WebRTC), so
`voices_empty` and similar aren't calibrated here — they need Tier-3 real-device data (a cross-browser
cloud matrix or opt-in collection from the hosted demo). This is Tier-1: real fingerprint *distributions*
for the 30 rules that depend on the static fingerprint, which is where the false positives concentrate.

## Second real-traffic source (Intoli) — and the critical FP it surfaced

A third tier of corroboration: the **Intoli `user-agents` dataset** (BSD-2-Clause; ~10k records resampled
from real site traffic), scored via `kitsune_harness.intoli_corpus` (fetched at runtime, not committed).
Unlike browserforge (a generated distribution skewed desktop) and the headless engine captures, this is
**real-traffic** and **~75% mobile** — the surface our desktop-oriented coherence rules are most likely to
mishandle. It emits only the coherence signals the dataset genuinely supports (UA / platform / vendor /
language); since the conviction gate lets only a convicting signal label `bot`, the verdict rate is a clean
measure of *coherence-driven* false positives on real traffic.

```sh
task calibrate-intoli            # uv run python -m kitsune_harness.intoli_corpus --n 4000
```

**It immediately found a showstopper the single source missed.** On 4000 real records:

| rule | browserforge (Tier-1) FP | Intoli real-traffic FP | verdict |
|---|---|---|---|
| `br.navplatform_vs_ua` | 3.6% | **73.1%** | **real, severe** — false-fires on real mobile |
| `br.vendor_vs_ua` | 0.4% | 0.3% | corroborated FP-safe |

A real Android browser carries `navigator.platform = "Linux …"` while its UA-platform is `Android` — a
legitimate, coherent pairing (Android is a Linux-family OS) that the platform-coherence rule read as a
contradiction, convicting **73% of real traffic** as `bot`. Browserforge (desktop-skewed) reported 3.6% and
missed it entirely. This is the over-leverage guard inverted: the single source *under*-counted a catastrophic
FP, and only the independent real-traffic source revealed it. The fix is per-platform OS-family normalization
(Android ↔ Linux), handled in the per-browser detection work.
