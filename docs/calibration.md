# calibration — measuring false positives on real browsers

The evader scoreboard proves rules *catch bots*. This proves they *don't flag humans*. It is the
empirical backstop for the precision problem: a real but unusual browser (desktop with no webcam, a
non-Retina Mac, a VM, an ad-blocker) trips single-layer `environment` tells that noisy-or then
accumulates into a `bot` verdict — a false positive. Same discipline the biomech rules got from the
Balabit calibration, now generalised to the fingerprint layer.

## Grounding-source status (2026-06-19) — what's grounded against what, and what needs operator capture

Consolidated map of which detection references are cross-checked against an independent source vs.
browserforge-only (the per-finding detail is in the re-validation log below). The standing rule: never act
on a single source — corroborate first.

| layer / factor | independent grounding source | status |
|---|---|---|
| **behavioural biomech** (path/velocity/keystroke) | Balabit mouse-dynamics dataset | ✅ grounded (original design) |
| **prevalence — screen** | Intoli real-traffic resolutions | ✅ grounded (drove the size-class bucketing) |
| **network — TLS JA4** (`net.tls_vs_ua_browser`) | FoxIO JA4 reference | ✅ Chrome cipher hash confirmed; edge JA4 = spec |
| **network — PQ keyshare** (`net.*_pq_keyshare_vs_ua`) | IANA registry + 2026 deployment | ✅ X25519MLKEM768/0x11EC current + FP-safe |
| **network — HTTP/2** (`net.h2_header_order_vs_ua`) | Akamai HTTP/2 standard (BlackHat) | ✅ Chrome `m,a,s,p` + SETTINGS confirmed |
| **IP reputation** (`rep.*`) | AWS/GCP/Tor public ranges (refresh tool) | ✅ CIDR data public; live exercise needs proxy egress |
| **network — Safari/Firefox JA4** | FoxIO `ja4plus-mapping.csv` | ✅ real-browser JA4s ADDED (corroborated 2 sources; edge JA4 proven spec-compliant) alongside the Playwright hints |
| **prevalence — cores** | Steam HW survey | ⚠ flag: browserforge may over-generate high cores (corroborate, don't act) |
| **prevalence — gpu** | none (Steam gamer-skewed; Web3DSurvey lacks vendor table) | ✗ needs web-representative capture |
| **`chrome_runtime_authenticity`** | none (docs ≠ verification) | ✗ needs live real-Chrome capture |

The whole **network-coherence seam** (the layer Ulixee-Hero-class tools attack) is grounded end-to-end
against external standards. The remaining ✗/⚠ items have **no clean public dataset** — they require capturing
real browsers/traffic/proxies through our own stack, which the turnkey infra (`--build-prior-from-sessions`,
`PROXIES=`, a real-browser edge capture) consumes.

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

This Tier-2 proof is now **CI-guarded** (`harness/tests/test_calibration_methodology.py`, re-confirmed live
at ruleset 0.74.21) on two independent paths:

- **Mapper path** (`engines/`, headless references through `signals_from_fingerprint`): Chromium/Firefox
  produce **zero** coherence+artifact contradictions, the only coherence fire anywhere is WebKit's
  `br.navplatform_vs_ua` (the Playwright-on-Linux Mac-UA quirk, not real Safari), and `br.webgl_not_angle`
  fires on no real engine.
- **Mapper-FREE path** (`headful/`, real collector signals from clean headful xvfb captures — the closest
  thing the lab has to a real user's browser): no BROWSER-layer (`br.*`) fingerprint coherence/artifact rule
  false-fires on real headful Chromium/Firefox; WebKit's only `br.*` coherence fire is again the
  `navplatform` quirk. The NETWORK-layer (`net.*`) coherence fires on Playwright Firefox/WebKit (TLS/QUIC
  GREASE, h2 order, `tcp_os`) are explicitly **out of scope** — patched-build network-stack artifacts, not
  real Firefox/Safari; acting on them would need a non-Playwright capture (the no-single-questionable-source
  discipline). Real headful Chromium, whose Playwright network stack IS representative, is fully clean.

A future mapper/rule change that reintroduced a false browser-layer coherence/artifact fire on a real engine
now fails the build instead of silently inflating a single-source FP number.

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

### Mapper fidelity & coverage scope (audited 2026-06-19)

The standing constraint demands we prove the mapper (`signals_from_fingerprint`) emits what a REAL browser
emits. A signal-KIND diff — the mapper over generated/real fingerprints vs. the kinds the real headful
Chromium/Firefox/WebKit captures emit — settles both directions:

- **Mapper emits, real captures don't:** only `font_os_hint` and `webgl_not_angle`. `font_os_hint` is
  **faithful** — the mapper's per-OS signature font lists (`Segoe UI`/`Calibri`/… etc.) and its ≥2-match
  threshold are identical to the collector's `fontOSHint()`; it's simply absent from the sparse-font test
  container, not fabricated. `webgl_not_angle` is the documented browserforge **renderer-generation
  artifact** (its generated GPU strings aren't ANGLE-wrapped); it is environment-category, so it can only
  ever corroborate, never convict — its ~1.8% "FP" is browserforge being unrealistic, not a real-browser FP.
- **Real captures emit, mapper doesn't (35 kinds):** every `net.*` kind (`ja3`/`ja4`/`h2`/`tcp_kernel`/
  `tls_no_grease`/`quic_*`), every behavioural kind (`mouse_*`/`trace_hash`/`pause_ratio`/`submovement_*`),
  the automation kinds (`cdp_runtime_enabled`/`chrome_runtime_missing`), and `webgpu_*`/`voices_empty`/CH
  headers. **This is the load-bearing caveat:** browserforge has no network/behavioural/automation/CH/webgpu
  layer, so the FP gate run through it measures ONLY the ~21 browser-fingerprint-coherence kinds — it is
  **structurally blind** to those 35. The headline "≈80% human (n=500)" therefore validates the
  browser-coherence rules only; the `net.*`, automation, and behavioural convicting rules are validated
  against the **live evader fleet** (their first live positives), the **headful captures**, and **Intoli**
  — never browserforge. Reading the browserforge number as "the FP rate" would over-trust a single source
  that cannot even see most convicting rules.

The 21-kind scope is pinned by `harness/tests/test_mapper_coverage.py` over the committed real engine
fingerprints (no browserforge needed): if a future mapper change adds or drops a measured kind, the test
fails, forcing a conscious update here + a re-check that the new kind is faithful to the collector (not a
mapper artifact like an early `navigator.platform` / `color_depth` / iOS-`vendor_vs_ua` would have been).

**Value-level fidelity (2026-06-19) — the methodology proof, completed.** Kinds matching isn't enough; the
mapper must emit the right *values*. We hold both halves per engine: the **fingerprint**
(`corpus/calibration/engines/<e>.json`, the mapper input) and the real **collector session**
(`corpus/calibration/headful/<e>.json`, what the live in-page collector emitted for that engine). Running
`signals_from_fingerprint` on the fingerprint and diffing against the collector's signals, **43 of 44 shared
values match exactly** across Chromium/Firefox/WebKit (Firefox 14/14, WebKit 15/15, Chromium 14/15). The lone
diff — Chromium `plugins_count` mapper **0** vs collector **5** — is NOT mapper infidelity: the engine
fingerprints are **headless** Playwright captures (they carry the headless stripped-browser tells —
`plugins_count` 0, `mimetypes_empty`, `chrome_no_pdfviewer`), while the headful session has the 5 standard PDF
plugins. So the mapper faithfully reproduces whatever the input fingerprint says. **Implication:** the engine
fixtures are a valid baseline for the **coherence/artifact** convicting categories (which match exactly — the
methodology claim `test_calibration_methodology` rests on), but NOT for the headless-environment tells. Pinned
by `harness/tests/test_mapper_value_fidelity.py` (every shared value must match except a documented, self-
guarded headless/headful allowlist), so a future mapper change that produces a wrong *value* — a calibration
artifact deeper than a wrong kind — fails CI.

### Second-source coherence FP-check (fpgen, 2026-06-19) — `task coherence-corroborate`

**Six** convicting COHERENCE rules were FP-checked against **browserforge alone** (Intoli can't reach them: it
carries no fonts / WebGL renderer / reliable platform / voices / WebGPU). **fpgen** (Scrapfly's generator —
independent data, see the prevalence-corroboration) is the only available second source with those fields, so
it now corroborates them (`kitsune_harness.fpgen_coherence`, `task coherence-corroborate`), scoped to exactly
the rules whose operands map faithfully from fpgen; `vendor_vs_ua`/`oscpu_vs_ua` are excluded because fpgen
nulls `navigator.vendor` and sets `oscpu` to "undefined":

- **Four via the standard mapper** — `br.font_os_vs_ua`, `br.webgl_os_vs_ua`, `br.navplatform_vs_ua`,
  `br.productsub_vs_ua` (operands from UA / platform / WebGL renderer / fonts / productSub).
- **Two runtime-derived** — `br.voice_os_vs_ua` and `br.webgpu_vendor_vs_webgl`, the **least-calibrated**
  convicting rules (their only prior FP grounding was unit tests + 3 headful captures). `fpgen_coherence`
  replicates the collector's *exact* `voice_os` (TTS-name regex) and WebGPU/WebGL `gpu_family` derivations
  (hermetically tested for fidelity) over fpgen's `voices` / `gpuInfo`.

Result over ~300: **`webgl_os` / `navplatform` / `productsub` / `voice_os` / `webgpu_vendor` all 0%**;
`font_os_vs_ua` ~0.3–1.3%, and that is **not** a real-browser FP — the firings are fpgen GENERATION
incoherences (a *Windows* UA + Windows platform generated with *macOS* fonts like `Al Bayan` a real Windows
machine never has), which the rule **correctly** catches. So all six are corroborated FP-safe on a second
independent population; their only firings are the generator's OS-incoherent joints (same class as
browserforge's `media_devices_empty`/`webgl_not_angle` artifacts). The font/OS incoherence is fpgen-specific
(browserforge `font_os_vs_ua` ~0%) — a Scrapfly-data trait, not family-wide. Caveat: fpgen is a generator, so
this is a generator-vs-generator check, weaker than the real-browser value-level fidelity above; a *spike* over
the ~1% generator floor would flag a true FP to investigate.

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
| `userAgent` ↔ `vendor` | **device-faithful but axis-decoupled on iOS** | chromium↔Google / safari↔Apple on desktop+Android, but on **iOS the axes legitimately decouple** — see the `vendor_vs_ua` iOS FP below |
| `screen` | **yes** | 99% of iPhone UAs report width ≤ 500 |
| `language` | **yes** | tracks UA region |
| `navigator.platform` | **no** | **70% report `"Linux x86_64"` regardless of device** — iPhones (real: `iPhone`), arm Androids (real: `Linux armv8l`), and Macs alike. A collection-environment value leaking into the field. |

So a naive run that derived `nav_platform_os` from the `platform` field convicted **~73%** of records on
`br.navplatform_vs_ua` — but that number is **mostly a dataset artifact**, not a real-browser FP: it is the
fabricated mismatch of a real iPhone/Mac/Android UA against a fixed `Linux x86_64` platform that no such
device actually reports. The corpus therefore **cannot measure platform-coherence FP**, and the mapper
omits `navigator.platform` entirely. What it *can* measure — `vendor_vs_ua`, engine, language, screen.

| rule | browserforge (Tier-1) FP | Intoli real-traffic FP | verdict |
|---|---|---|---|
| `br.vendor_vs_ua` | 0.8% (desktop, browserforge's own gen incoherence) | 1.4% → **0.1%** after the iOS gate (v0.74.22) | **second source caught a real FP** — see below |
| `br.navplatform_vs_ua` | 3.6% | *not measurable* | Intoli's `platform` field is unreliable; see above |

**The second source earned its keep: `br.vendor_vs_ua` convicted real iOS browsers (v0.74.22).** The
single-source (browserforge, desktop-heavy) calibration rated `vendor_vs_ua` FP-safe; a fresh mobile-heavy
Intoli run showed it firing on **1.4% (55/4000)** as a *hard bot* false positive — a **convicting coherence
rule** mislabelling real traffic. Drill-down (all 10k records): the firings are two legitimate iOS patterns —
real **Chrome-on-iOS** (`CriOS …Safari/604.1` → `ua_engine` safari, but `navigator.vendor` = `Google Inc.` →
`vendor_engine` chromium, 107×) and iOS **in-app WebViews** (no Safari token → `ua_engine` "other", vendor
`Apple…`, 7×). Root cause: Apple forces WebKit for *every* iOS browser, but `navigator.vendor` follows the
**brand**, so the vendor and UA-engine axes decouple — the desktop "vendor must match UA engine" assumption
is false on iOS. **Fix:** the collector + both calibration mappers no longer *emit* `vendor_engine` on an iOS
UA (`/iPhone|iPad|iPod/`), so the rule abstains there ("unknown never fires") — narrowing only. **No coverage
lost:** an iOS-UA spoof on a Chromium host is still convicted structurally by `br.apple_ua_nonwebkit`
(`window.chrome`/`userAgentData` on a claimed-WebKit host). The two residual patterns split: a **macOS Safari
UA reporting vendor `Google Inc.`** (no real Safari does — a Chromium-crawler-faking-Safari signature, `4×`)
is a genuine TRUE POSITIVE the rule keeps; but the **bare `AppleWebKit (KHTML, like Gecko)` macOS UA with no
browser token** (`2×`) classifies as `ua_engine=other` (unclassifiable — most likely a real macOS WKWebView
whose vendor is correctly `Apple`), and convicting on a comparison whose engine operand is UNKNOWN violates
*unknown never fires*. **v0.74.23 (Intoli second-source re-run on the refreshed dataset):** `vendor_engine` is
now also withheld when `ua_engine == "other"`, so the rule abstains on an unclassifiable engine — the `other`
firings drop `2 → 0` while the Safari-UA-+-Google-vendor true positive stays `4 → 4`. browserforge is
unaffected (its UAs are classifiable, so the gate only ever lowers the flag rate). Mirrored across
`demo.py` / `calibration.py` / `intoli_corpus.py` / `livepage/probes.ts`; guarded by `test_intoli_corpus.py`
(iOS abstains, real Chrome-iOS clean, real macOS-WKWebView clean, and both the desktop-mismatch and
macOS-Safari-+-Google-vendor true positives still convict).

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

- **2026-06-19 · ruleset 0.74.19** — full live re-validation after the WebKit-engine additions
  (WebKit JA4 hint, br.safari_ua_no_webkit_api, webkit-ua-spoof evader). Live stack rebuilt to 0.74.19.
  Engine-identity family all fire live: `net.tls_vs_ua_browser` (webkit-ua-spoof → bot, WebKit JA4 hint
  working), `br.firefox_ua_nongecko` (spoof-ua), `br.safari_ua_no_webkit_api` (ios-ua-spoof). Named
  experimental rules fire live: `br.readback_noise` (audio-readback-spoof), `net.h2_header_order_vs_ua`
  (http2-naive). Stealth fleet drift check: selenium-driverless, PATCHRIGHT, REBROWSER all → `bot` (1.00,
  5–7 convicting tells each). No drift. Matrix 51/52 (camoufox-headful the lone `suspicious`, a raw-SYN
  capture miss).

- **2026-06-19 · ruleset 0.74.21** — full live re-validation after the prevalence hardening (colour-factor
  drop v0.74.20, cores-bucket coarsening v0.74.21) and the coordination/IP-reputation work. Live stack
  confirmed at 0.74.21 (`docker exec` on the running detector). Both named experimental rules re-validated
  TRUSTED-BUT-VERIFIED on both sides:
  - **Fire on the evaders that should trip them.** `br.readback_noise` fires live (audio-readback-spoof →
    `bot`, score 1.00, artifact category alongside 6 automation convictions). `net.h2_header_order_vs_ua`
    fires live (http2-naive = vanilla `KS_HTTP2=1` + Chrome `KS_UA` → `bot`, score 1.00) — and a SECOND
    independent live positive this run: `undetected` (undetected-chromedriver) also trips it → `bot`.
  - **Stay clean on a real engine.** A fresh Tier-2 headful Chromium capture (xvfb, clean Playwright, the
    genuine collector) at 0.74.21 → both `br.readback_noise` and `net.h2_header_order_vs_ua` CLEAN; the only
    convicting rules are the expected Playwright automation tells (`webdriver_present`, `cdp_runtime_enabled`,
    `chrome_runtime_missing`). No fingerprint-coherence/artifact rule fires on the real engine — the
    methodology invariant holds at the current ruleset.
  - Base anti-detect fleet drift check: `nodriver`, `undetected`, `pydoll` all → `bot` (score ≥0.999, ≥2
    convicting tells each). No drift. Matrix/scoreboard confirmed current at 0.74.21 (re-scored captures
    match live behaviour). No rule semantics changed → no ruleset bump (verification, not a new rule).

- **2026-06-19 · ruleset 0.74.21 · `br.readback_noise` promotion review** — checked whether the experimental
  `br.readback_noise` is promotable to active. Promotion needs an INDEPENDENT second positive (cf. how
  `net.h2_header_order_vs_ua` was promoted only after curl corroborated httpx). A fresh **live Camoufox**
  capture (an independent engine-level anti-detect browser) → `bot 0.997` but does **NOT** trip
  `br.readback_noise` — no audio-divergence signal at all. Camoufox sets no privacy-browser identity, so
  applicability does not drop it: the absence is real signal — its readback is internally CONSISTENT across
  `getChannelData`/`copyFromChannel` (a quality tool, not a naive one-path shim). This **corrects** the rule's
  prior source note (which claimed Camoufox trips it — it does not). So the only live positive remains the
  deliberately-inconsistent `AUDIO_READBACK_SPOOF` shim; with no independent corroboration the rule **stays
  experimental** (promoting on a single self-constructed positive would be single-source over-leverage). Its
  real-browser negative is CI-guarded (`test_calibration_methodology`). No semantics changed → no ruleset bump.

- **2026-06-19 · ruleset 0.74.21 · cutting-edge CDP-patched fleet drift check** — re-validated the most
  advanced anti-detect tools live (the ones engineered to defeat the automation tells), none previously
  drift-checked at 0.74.21: `selenium-driverless`, `zendriver`, `patchright` (CDP-patched Playwright drop-in),
  `rebrowser` (Runtime.enable-leak fix), `max-stealth` (full combined battery). **All five → `bot`** (score
  ≥0.999): selenium-driverless and zendriver 3 convicting each, patchright 6, rebrowser 8, max-stealth 3.
  No drift, no evasion. `net.quic_grease_vs_ua` fired on all five in these (long) runs.

  **CORRECTION (next iteration, grounded):** that initial read overstated `quic_grease` as "the universal
  backstop." It reads `network.quic_no_grease` (present-predicate), which the edge emits ONLY when the
  session lives long enough for Chromium to retry over h3/QUIC after learning the edge's Alt-Svc — so it is
  **timing/session-length-dependent for recall** (real headful Chromium and the committed `full-stealth`
  capture emit NO QUIC signal at all and do not trip it). It is FP-safe (real Chrome GREASEs its QUIC →
  `quic_no_grease` never present), but it is a **bonus catch, not the reliable backstop.** Re-verified that
  each tool still convicts on **deterministic** tells with `quic_grease` excluded: patchright → 5 browser
  tells (`headless_ua`/`ch_he_headless`/`permissions_anomaly`/`no_chrome_object`/`notification_denied`),
  selenium-driverless → `headless_ua` + `chrome_runtime_missing`, max-stealth → `net.ch_ua_version_vs_ua` +
  `net.no_js_execution`, zendriver → `h2_header_order` + `chrome_runtime_missing`, rebrowser → `webdriver` +
  `cdp_runtime_enabled` + more. So the robust backstop is the **deterministic h2-layer + browser-layer**
  tells (each tool caught ≥2 ways), and the "no evasion at 0.74.21" conclusion holds independent of the
  timing-dependent QUIC catch. No rule semantics changed → no ruleset bump.

  **SCOPE CAVEAT (next iteration):** the patchright-engine configs (`patchright`, `max-stealth`) are caught,
  but `max-stealth` and any `patchright + spoof/UA` are caught by `net.no_js_execution` because patchright
  breaks our evader's own page collector (zero browser signals) — an over-spoofing/collector-break artifact,
  NOT a defeat of the browser-layer tells, and the spoofs do not even apply under patchright. So the
  genuinely-evasive config (patchright-class CDP stealth + coherent non-headless UA + a WORKING collector)
  is **untested** by the current fleet. See docs/evasion-catalog.md "Known red-team-fleet limitation". The
  "no evasion" claim is honest for what the fleet exercises, but the browser-layer-under-patchright frontier
  is open.

  **RESOLVED (same day):** added a `HEADFUL=1` flag and captured headful patchright with a working collector
  (`corpus/sessions/patchright-headful.json`, 20 browser + 10 behavioural signals). It is caught — `bot` 1.00
  — and the robust browser-layer catch is **`br.chrome_runtime_missing`**: patchright defeats CDP + the
  headless tells but does not restore `window.chrome.runtime`. So the browser layer DOES hold against
  patchright-class stealth; the frontier is now tested, not open. The thin remaining path (also faking
  `window.chrome.runtime` — itself a native-invariant artifact) is the next red-team probe. Matrix now 52/53
  `bot` (patchright-headful added; camoufox-headful the lone `suspicious`).

- **2026-06-19 · ruleset 0.74.21 · periodic experimental-rule re-validation** — both named experimental
  rules re-confirmed firing live through the edge→detector stack (healthy): `br.readback_noise`
  (audio-readback-spoof → `bot`) and `net.h2_header_order_vs_ua` (http2-naive → `bot`). No drift; live stack
  at 0.74.21. Their real-browser negatives stay CI-guarded by `test_calibration_methodology`. Per-session
  detection remains saturated; the threat-model exploration (per-session ceiling → prevalence same-source
  blindness → coordination per-cluster ceiling → durable signals = `shared_real_ip`/`trace_collision` +
  population statistics) is complete and the residual frontier is external-data-bound. No rule changed → no
  ruleset bump.

- **2026-06-19 · ruleset 0.74.21 · structural-frontier (coordination) re-validation** — re-ran the live
  cloned-fleet capture (`fleet_capture.sh`, N=3 concurrent, distinct container IPs) through the healthy
  edge→detector stack and graded with the live coordination detector → `fleet` **1.00**. Both top-priority
  durable signals fired: `fp_collision` (identical high-entropy fp `bf779223` across 3 IPs) AND the
  unambiguous `trace_collision` (identical pointer trace across 2 IPs) — the two signals the threat model
  (docs/evasion-catalog.md "Coverage envelope") identified as the durable catches a sophisticated fleet must
  suppress. No drift; the structural frontier works live. Refreshed `corpus/fleet-cloned/cn1-3.json`; the 34
  coordination unit tests pass on the fresh fixture. No rule changed → no ruleset bump.

- **2026-06-19 · ruleset 0.74.21 · periodic re-validation (live fleet + matrix)** — explicitly-requested
  recurring check (~9 iterations since the last). Live stack healthy; both named experimental rules fire
  live: `br.readback_noise` (audio-readback-spoof → bot) and `net.h2_header_order_vs_ua` (http2-naive → bot).
  Cutting-edge drift sample: `nodriver`, `patchright` → bot. Matrix re-scored vs committed → NO DRIFT at
  0.74.21. Nothing changed (ruleset + evader images pinned); confirms the live deployment still behaves. No
  rule changed → no ruleset bump.

- **2026-06-19 · network-layer grounding — Chrome JA4 validated against the FoxIO JA4 reference** — acting on
  the "find more grounding sources" directive, cross-checked the edge's JA4 hint table
  (`edge/internal/fingerprint/ja4_hints.json`) against an independent public source (FoxIO JA4 spec/docs). Our
  Chrome cipher hash **`t13d1516h2_8daaf6152771` matches** the documented current-Chrome JA4
  (`t13d1516h2_8daaf6152771_…`, "real Chrome 119 pattern") — confirming the TLS→browser ground truth for
  `net.tls_vs_ua_browser` against a second source. The extension hash (JA4_c) legitimately varies by
  config/version, which is exactly why the hint table prefix-matches on the STABLE cipher hash (JA4_a+JA4_b)
  and tolerates the variable JA4_c — design validated. (The firefox `5b57614c22b0` / safari `723694b0fccc`
  cipher hashes come from the live headful Firefox/WebKit captures; the full FoxIO DB file would broaden
  per-version recall but is a deploy-time edge refresh — FP-safe either way, since an unhinted JA4 never
  convicts.) No rule changed → no ruleset bump.

- **2026-06-19 · network-layer grounding — Safari/Firefox JA4 hints are Playwright-build-specific (finding)**
  — continued the grounding search to the Firefox/Safari hints. The documented REAL Safari iOS 18.3 JA4 is
  `t13d2014h2_a09f3c656075…` (curl_cffi #460 / FoxIO), but our hint is `t13d2914h2_723694b0fccc` — DIFFERENT
  cipher count (20 vs 29) AND hash. So our safari hint is **Playwright-WebKit's** JA4, not real Safari's,
  confirming the documented "Playwright WebKit TLS ≠ real Apple Safari" caveat (same for the Playwright-Firefox
  hint `t13d1717h2_5b57614c22b0`; no clean public real-Firefox JA4 surfaced to compare).
  **FP-safety holds:** a real Safari (its own JA4, UA=safari) is UNHINTED → `net.tls_vs_ua_browser` cannot
  fire → no FP; and no real user produces Playwright-WebKit's JA4, so hinting it `safari` only convicts the
  `webkit-ua-spoof` evader (its point). **Coverage gap (disciplined, NOT acted on):** adding the REAL
  per-version Safari/Firefox JA4s would let the rule positively recognise real-browser TLS and catch a
  real-browser-TLS impersonator (e.g. curl_cffi-Safari) faking a mismatched UA — but that is a deploy-time
  grounding task: the values must be verified as what OUR edge computes (a live real-Safari/Firefox capture,
  or multi-source/multi-version corroboration) before entering the convicting path. Not a single-source
  unilateral edit. No rule changed → no ruleset bump.

- **2026-06-19 · network grounding — PQ-keyshare stale-template tells confirmed current (FP-critical)** — the
  Hero white-box flagged "stale template" as the coherence seam, so I grounded the PQ-keyshare reference
  (`net.tls_pq_keyshare_vs_ua` / `net.quic_pq_keyshare_vs_ua`, which fire on ABSENCE of a PQ key share under a
  current-Chrome UA — a false reference would FP on real Chrome). Cross-checked against public 2026 status:
  **X25519MLKEM768 (codepoint `0x11EC`/4588) is IANA-Recommended and remains Chrome's deployed PQ default**
  (Google/Cloudflare/Akamai all ship it through 2026). The edge's `HasPostQuantumKeyShare()`
  (`edge/internal/fingerprint/keyshare.go`) recognises BOTH `0x11EC` (standard) and `0x6399` (Chrome 124-130
  Kyber draft) — so a real current Chrome (offering 0x11EC) is seen as PQ-present → the rule **does not fire**
  → no FP. The reference + the edge's codepoint detection are both current; the stale-template seam is
  correctly grounded (catches a pre-2025 template lacking both codepoints, silent on real Chrome). No drift,
  no rule change → no ruleset bump.

- **2026-06-19 · network grounding — HTTP/2 fingerprint confirmed Chrome (completes the Hero-seam grounding)**
  — cross-checked the edge's h2 fingerprint `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`
  (`edge/internal/fingerprint/h2.go`, Akamai format) against the public Akamai HTTP/2 fingerprinting standard
  (BlackHat white paper / peet.ws): the pseudo-header order **`m,a,s,p`** (`:method,:authority,:scheme,:path`)
  is Chrome's, and the SETTINGS + WINDOW_UPDATE match Chrome's documented signature. The edge classifies the
  browser from the pseudo-header order — the most version-stable component (Firefox sends a different order),
  so it is FP-safe (real Chrome's `m,a,s,p` → hinted chrome → matches UA → no fire; a non-Chrome h2 order
  under a Chrome UA → `net.h2_header_order_vs_ua` / `h2_vs_ua` fire).
  **This completes the grounding of the network-coherence seam the Ulixee-Hero white-box flagged** — all
  three masked components are now validated current against external public references: TLS JA4 (Chrome cipher
  hash, FoxIO) · post-quantum keyshare (X25519MLKEM768/0x11EC, IANA/2026) · HTTP/2 (Akamai standard). The
  durable per-session catch for the cutting-edge fleet is grounded end-to-end. No rule changed → no ruleset bump.

- **2026-06-19 · JA4-hint deployment + periodic re-validation** — rebuilt and redeployed the edge image with
  the new real-browser JA4 hints (Safari/Firefox/Chrome-17), validating they build + run in the actual Docker
  image (the Go test confirms the `go:embed`, this confirms the containerised deploy). Live stack green with
  the new edge, no regression: `stealth` → bot, `http2-naive` → bot (`net.h2_header_order_vs_ua` fires),
  `audio-readback-spoof` → bot (`br.readback_noise` fires). Both named experimental rules re-validated. The
  additive JA4 hints don't change fleet verdicts (they fire only on real Safari/Firefox/17-ext-Chrome TLS,
  which the Playwright fleet doesn't produce). Edge change deployed + validated end-to-end. No rule changed →
  no ruleset bump.

- **2026-06-19 · ruleset 0.74.22 · periodic experimental-rule re-validation + fpgen-scope finding** — live
  stack healthy at 0.74.22; both named experimental rules re-confirmed: `net.h2_header_order_vs_ua` fires on
  http2-naive (vanilla `KS_HTTP2=1` + Chrome UA → bot), `br.readback_noise` fires on `audio-readback-spoof`
  (→ bot) AND does NOT fire on real Camoufox (engine-level audio = consistent — negative intact). Matrix
  current (zero content drift; only the scoreboard's `generated:` timestamp differs — cosmetic, not
  committed). **fpgen calibration-scope finding:** fpgen (the Scrapfly second source, see
  `kitsune_harness.fpgen_corroborate`) is faithful for the **distributional prevalence features**
  (gpu/screen/cores) but NOT for navigator-**coherence** rules — it nulls `navigator.vendor` (carries the
  WebGL vendor only) and sets `oscpu` to the literal string `"undefined"` with no `userAgentData`, so feeding
  it through `signals_from_fingerprint` would fabricate `vendor_vs_ua`/`oscpu_vs_ua` "FPs" that are mapper
  artifacts, not rule FPs. So fpgen corroborates the prevalence prior (done) but must NOT be used as a
  drop-in coherence FP source. No rule changed → no ruleset bump.

- **2026-06-19 · ruleset 0.74.23 · periodic experimental-rule re-validation + post-fix regression sweep** —
  live stack healthy at 0.74.23 (the `vendor_vs_ua` unknown-engine fix deployed). Both named experimental
  rules re-confirmed against the live fleet: `net.h2_header_order_vs_ua` fires on http2-naive (vanilla
  `KS_HTTP2=1` + Chrome UA → bot), `br.readback_noise` fires on `audio-readback-spoof` (→ bot) AND does NOT
  fire on real Camoufox (engine-level audio = consistent — negative intact). Regenerating the matrix from the
  committed captures changed **only** the ruleset stamp (`0.74.22 → 0.74.23`) — i.e. the `vendor_vs_ua`
  unknown-engine narrowing caused **zero** verdict change on any committed capture (none carry an
  unclassifiable-engine UA), confirming no regression. Also re-ran the coordination scenario eval:
  **precision 100% / recall 100%** (the 6 legit-cohort FP-cases — corporate fp_collision, multi-version JA4_c
  divergence, NAT shared-IP, etc. — all correctly cap at `candidate`, every fleet shape caught). Matrix +
  scoreboard refreshed. No rule changed → no ruleset bump.

- **2026-06-19 · ruleset 0.74.23 · Intoli precision re-run (refreshed dataset, n=6000) — gate green + a real
  positive.** Re-ran the second real-traffic source: **100% human / 0% suspicious / 2 bot (0.03%)**. Both
  `vendor_vs_ua` fixes hold — the only convicting firings are `ua_engine=safari` records (a macOS **Safari**
  UA reporting `navigator.vendor` "Google Inc."), and the 2 unclassifiable-engine (`other`) records in the
  data correctly **abstain** in the scoring path (the v0.74.23 narrowing emits no `vendor_engine` for them).
  Importantly those 2 firings are **not FPs — they are real Chromium-faking-Safari crawlers in genuine site
  traffic** (no real Safari reports a Google vendor; the `(Lanai)` UA suffix is a known crawler marker). So
  this is the **first demonstration that a Kitsune coherence rule convicts an actual crawler in a real-traffic
  dataset**, not just a synthetic fleet evader — `br.vendor_vs_ua` has real-world detection value, locked by
  `test_intoli_corpus.test_macos_safari_with_google_vendor_still_convicts`. The recurring Intoli re-run remains
  the highest-yield precision check (it caught the iOS and unknown-engine FPs); it is now clean. No rule changed.

- **2026-06-19 · ruleset 0.74.24 deployed + validated live — the prevalence threshold FP fix is now in
  effect.** The prevalence cross-source-threshold fix (v0.74.24) had been committed but the live detector was
  still serving the **stale 0.74.23** image (the over-flagging `-7.73` self-p1). Rebuilt + redeployed the
  detector; live stack now at 0.74.24 with the conservative `-9.484` (cross-source) threshold. Validated:
  `br.fingerprint_improbable` still fires on the 3 genuine improbable spoofs (`ios-ua-spoof`, `renderer-spoof`,
  `webkit-ua-spoof`) — **recall preserved** — while no real-browser capture and no clean stealth run trips it,
  and the whole committed corpus is unchanged at **57 bot / 1 suspicious** (every evader caught, the lone
  suspicious is a baseline real browser). A live `STEALTH=1` evader → bot at 0.74.24, `fingerprint_improbable`
  silent. Lesson logged: **after a prior-data or rule change, redeploy the live detector** — a committed fix
  isn't in effect until the running image is rebuilt. Also completed the self-referential-calibration audit:
  the bot/suspicious score cutoffs (`0.35`/`0.65`) are FIXED design constants, not browserforge-self-referential,
  so the prevalence threshold was the only self-calibrated number — now fixed. No rule changed → no ruleset bump.
