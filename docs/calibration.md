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

**`media_devices_empty` (the top FP at ~18%) is largely a browserforge generation artifact, not real FP
risk.** Generating 1500 browserforge fingerprints and bucketing the empty-`multimediaDevices` rate by
platform: **macOS 47%**, Windows 3%, Linux 3%, Android 5% — the ~18% overall is almost entirely macOS. But a
real Mac has a built-in microphone, speakers, and (usually) a camera, so `enumerateDevices()` is **never**
empty there (it returns ≥1 entry per kind even without permission). browserforge simply under-populates
macOS media devices; a real macOS browser does not trip the rule. So the headline number overstates the
real-world FP — a third instance of the same single-source trap as the Intoli `platform` field and the
prevalence screen factor. `media_devices_empty` stays a corroborating-only environment tell (the conviction
gate already prevents it convicting); it is **not** a down-weight/prune candidate on this inflated number.

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

## Second real-traffic source (Intoli) — verification, and what it actually showed

A third tier of corroboration: the **Intoli `user-agents` dataset** (BSD-2-Clause; ~10k records resampled
from real site traffic), scored via `kitsune_harness.intoli_corpus` (fetched at runtime, not committed).
Unlike browserforge (a generated distribution skewed desktop) and the headless engine captures, this is
mobile-heavy real traffic (~27% iPhone) — the surface our desktop-oriented coherence rules are most likely
to mishandle.

```sh
task calibrate-intoli            # uv run python -m kitsune_harness.intoli_corpus --n 4000
```

**Trusted-but-verified: before trusting any field as a coherence input, we checked it tracks the device.**
This is where the single-source guard earns its keep — an unverified FP number from one corpus is not
actionable. Field-by-field over the 10k records:

| field | faithful to the device? | evidence |
|---|---|---|
| `userAgent` ↔ `vendor` | **yes** (99.6%) | chromium↔Google, safari↔Apple; ~0.4% incoherent (matches browserforge) |
| `screen` | **yes** | 99% of iPhone UAs report width ≤ 500 |
| `language` | **yes** | tracks UA region |
| `navigator.platform` | **no** | **70% report `"Linux x86_64"` regardless of device** — iPhones (real: `iPhone`), arm Androids (real: `Linux armv8l`), and Macs alike. A collection-environment value leaking into the field. |

So a naive run that derived `nav_platform_os` from the `platform` field convicted **~73%** of records on
`br.navplatform_vs_ua` — but that number is **mostly a dataset artifact**, not a real-browser FP: it is the
fabricated mismatch of a real iPhone/Mac/Android UA against a fixed `Linux x86_64` platform that no such
device actually reports. The corpus therefore **cannot measure platform-coherence FP**, and the mapper
omits `navigator.platform` entirely. What it *can* measure — `vendor_vs_ua` (0.3% vs browserforge 0.4%),
engine, language, screen — corroborates the browserforge coherence numbers.

| rule | browserforge (Tier-1) FP | Intoli real-traffic FP | verdict |
|---|---|---|---|
| `br.vendor_vs_ua` | 0.4% | 0.3% | corroborated FP-safe |
| `br.navplatform_vs_ua` | 3.6% | *not measurable* | Intoli's `platform` field is unreliable; see above |

**The genuine sub-problem, fixed independently (v0.71.1).** Buried inside the artifact is a real issue we
could ground without Intoli: a real Android browser *does* carry `navigator.platform = "Linux armv8l"` under
an `Android` UA — a legitimate, coherent pairing (Android is a Linux-family OS) that the platform-coherence
rule would read as a contradiction, false-firing on **every** real Android visitor. The fix is **OS-family
resolution** at signal derivation: before the platform-coherence rules compare, a `Linux` kernel hint
(`navigator.platform`, `oscpu`, or the WebGL OS hint) is resolved to the device's true OS *family* relative
to the UA — under an Android UA, `Linux` IS `Android`. Applied at every **real-browser** derivation site
(detector `demo.py`, collector `probes.ts`, harness `calibration.py`) so all three platform-coherence rules
(`navplatform_vs_ua`, `webgl_os_vs_ua`, `oscpu_vs_ua`) agree. Desktop OS impersonation (a Linux host claiming
a Windows UA) is untouched and still fires — the Camoufox counter is intact. This is validated against
real-browser behavior and the detector's own Android precision case, **not** against Intoli's unreliable
field.

## Convicting-rule FP audit (v0.74.x) — eight rules that flagged real users

The browserforge FP gate is blind to runtime probes (canvas/audio/webrtc/webgpu/adblock/…) — the static
mapper never emits them — so a convicting rule could false-fire on a real browser and pass every static
check (browserforge, the Tier-2 engine-corpus test, unit tests) clean. Scoring real captures + scrutinising
each convicting rule against *real* browser behaviour surfaced eight such rules. Each asserted a
"a real browser always/never does X" invariant where X is actually a **build / config / hardware / privacy**
choice; the fix demoted the soft signal to corroborating-only (or fixed the derivation / retired it), while
keeping every genuinely-hard convicting tell.

| rule | the "always/never" it assumed | the real browser that breaks it | fix |
|---|---|---|---|
| `math_engine_vs_ua` | `Math.pow(PI,-100)` ULP is engine-stable | a V8 build returning the "Firefox" value (node 22 ≠ Playwright Chromium) | retired |
| `webrtc_unavailable` | a real browser never disables WebRTC | privacy config (about:config, uBO, Brave, enterprise) | → environment |
| `font_linux_leak` | Arimo/Cousine/Tinos are Linux-only | Croscore fonts installed from Google Fonts on any OS | → environment |
| `codec_os_incoherent` | a real desktop always has H.264/AAC | open-source Chromium (no proprietary codecs) | → environment |
| `webgl_os_vs_ua` | Vulkan/OpenGL/SwiftShader ⇒ Linux | software rendering / non-default ANGLE on Windows/macOS | derivation: OS-exclusive stacks only |
| `webgpu_webgl_vs` | a real GPU drives both WebGL and WebGPU | WebGPU support ⊊ WebGL support (older GPUs) | → environment |
| `webgl_not_angle` | modern Chrome always reports ANGLE(...) | Linux/legacy Chrome with native GL | → environment |
| `adblock_present` | (its own note: "humans run adblockers") | 40%+ of users run uBO / AdBlock / Brave Shields | → environment |

**Cumulative impact:** zero detection loss on the spoof fleet — 44 of 45 captured evaders still score `bot`
(only headful `camoufox-headful`, whose *sole* conviction was the privacy-config WebRTC signal, correctly
drops to `suspicious`). The hard cross-layer tells (`tcp_os_vs_ua`, `ua_platform_vs_ch_platform`,
`cdp_runtime_enabled`, `native_invariant_violated`, the worker-realm divergences, …) carry every evader.
Locked in by `detector/tests/test_fp_regression.py`.

### Checklist before categorising a rule as convicting (coherence/automation/artifact)

A convicting rule can unlock the `bot` label; the conviction gate trusts it not to fire on a real human.
Before shipping one, ask — **can a real browser produce this exact signal via any of:**

1. **a browser build?** (Chromium-vs-Chrome codecs, a V8/CPU float quirk, Linux native-GL vs ANGLE)
2. **a user/OS config?** (WebRTC off, an ad-blocker, an installed font/voice pack, a non-default GPU backend)
3. **hardware?** (an old GPU lacking WebGPU, software rendering on a VM/RDP/blacklisted driver, a touchscreen)
4. **a privacy browser's by-design defense?** (Brave/Tor/Mullvad farbling — see `detector.applicability`)
5. **a network middlebox?** (an explicit corporate proxy presenting its own TCP/OS — the open `tcp_os_vs_ua`
   question, deferred pending a real-proxy capture)

If **yes** to any, the signal is *configurable/variable* → category **environment** (corroborates, never
convicts). Only a signal a real browser **cannot** produce — a spec invariant, a hard engine API, a
cross-realm divergence, an injected-code artifact — earns a convicting category. Five of the eight FPs above
were rules whose *own source text already said* "corroborating" / "weak alone" yet sat in a convicting
category: the category, not the description, is what the conviction gate reads.

## Tier-2: a real headful-browser source (`harness/tools/headful_capture.mjs`)

The standing constraint demands a *second, independent* calibration source besides browserforge (a
generated distribution). `headful_capture.mjs` is it: a clean, **no-spoof** Chromium / Firefox / WebKit,
launched **headful under xvfb** (the Playwright container's three real engines) and driven only enough to
navigate the live `edge → detector` spine, so the captured session is exactly what the genuine in-page
collector emits. Captures land in `corpus/calibration/headful/`. Unlike browserforge (a static field
distribution) or Intoli (real UAs but no runtime fields), this exercises the **runtime probes** — canvas,
audio, WebGL, CDP, and the engine-API tells — that the static mappers can't model. Run:

```sh
docker compose up -d detector edge
NET=kitsune_default; for e in chromium webkit; do \
  docker run --rm --network $NET -v "$PWD/harness/tools/headful_capture.mjs:/app/c.mjs:ro" \
    -e ENGINE=$e --entrypoint sh kitsune-stealth:latest -c 'cd /app && xvfb-run -a node c.mjs'; done
```

A Playwright-driven browser legitimately trips the **automation** tells (`webdriver`, CDP `Runtime.enable`)
and the container **environment floor** (`webgl_software`, `voices_empty`, `media_devices_empty`) — those
are expected and correct. The methodology check is narrower: **no fingerprint-coherence/artifact rule may
fire on the real engine's genuine fingerprint.** Two findings from the first run, both invisible to
browserforge (runtime probes the mapper omits) — the second source earning its keep:

1. **Confirmed the `math_engine_vs_ua` retirement (v0.74.0).** The stale live image (then at ruleset 0.73.9)
   convicted a real headful Chromium via `math_engine_vs_ua` — empirical proof the `Math.pow(PI,-100)` ULP
   is V8-build-dependent, not engine-stable. Rebuilding to the current ruleset cleared it.
2. **Found a new convicting FP: `apple_ua_nonwebkit` (fixed v0.74.9).** A real WebKit 18.4 engine (Playwright
   WebKit, vendor "Apple Computer, Inc.") exposes `Error.captureStackTrace` as a function — because **JSC
   added it in Safari 16.4 (2023)** — while correctly lacking `window.chrome` / `userAgentData`. The rule's
   third arm treated `captureStackTrace` as Blink-only, so it convicted **every real Safari 16.4+/iOS user**.
   Dropped that arm (kept the two genuinely-Blink-only APIs); re-capture confirms the real WebKit no longer
   trips it, while the `ios-ua-spoof` evader (Chromium under an iOS UA, `window.chrome` present) still does.
   A counter-check grounded the sibling rule too: `engine_stack_vs_ua`'s `firefox && captureStackTrace` arm
   is *safe* — a live Firefox 137 reports `captureStackTrace` undefined (SpiderMonkey has not shipped it), so
   that arm was left untouched. Acting on the unverified "Firefox added it" memory would have been the FP.
3. **Found a third convicting FP: `webgl_renderer_artifact` on Firefox (fixed v0.74.10).** Once the Firefox
   capture worked (it had hung on `waitUntil:"load"` — the CSP-blocked probe `<img>` never lets Firefox's
   load event settle; `domcontentloaded` fixes it), a real headful Firefox 137 reported its WebGL renderer as
   `"llvmpipe, or similar"` and tripped `br.webgl_renderer_artifact` — a convicting `artifact` rule (weight
   0.8). But `", or similar"` is **Firefox's own WebGL renderer GENERALISATION**, a fingerprinting-resistance
   feature ON BY DEFAULT in every Gecko browser (Firefox, Tor, Mullvad, Camoufox), not a fake-driver
   placeholder. It was the **only** corpus session — evader or real — that tripped this rule (the exact
   pure-FP profile of the retired `webgl_not_angle`). Fix: `detector.applicability` drops it when
   `ua_engine==firefox`; the rule stays convicting on Blink (which never emits that format). Camoufox
   detection is unaffected (it is caught by `tcp_os_vs_ua` / `tls_grease` / `pointer_touch`, not this rule).
   _Deferred:_ the Firefox capture also tripped `net.tls_grease_vs_ua` / `net.quic_grease_vs_ua` (it sent no
   TLS/QUIC GREASE), but Playwright's Firefox is a **patched build** whose network stack may not match real
   Firefox — so the GREASE question needs a non-Playwright real-Firefox capture before acting, and was left
   untouched (the same "don't act on a single questionable source" discipline as the `tcp_os_vs_ua` proxy
   question).

## Live re-validation log

Periodic re-validation of the experimental/named rules + the base anti-detect fleet against the LIVE
edge→detector stack (not just re-scored captures), per the standing loop directive. Each entry confirms the
committed captures still match live behaviour (no evader-tool or stack drift) at the recorded ruleset.

- **2026-06-19 · ruleset 0.74.18** — live stack confirmed at 0.74.18. `br.readback_noise` fires live
  (audio-readback-spoof → bot). `net.h2_header_order_vs_ua` fires live (http2-naive → bot). Base anti-detect
  fleet re-run live: `nodriver`, `undetected`, `pydoll`, `zendriver` all → `bot` (score 1.00, ≥2 convicting
  tells each). No drift. The recent rule additions (tls_vs_ua_browser, accept_lang, oscpu_vs_ua,
  firefox_ua_nongecko, safari_ua_no_webkit_api, honeypot_interaction) were each live-validated in their
  shipping iteration and are reflected in matrix.md (50/51; camoufox-headful the lone `suspicious`, a raw-SYN
  capture miss — `net.tcp_os_vs_ua` convicts it when the SYN is captured).
