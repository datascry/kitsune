<!-- docs/findings — empirical results from running the evader fleet against the detector. -->
<!-- The arms-race ladder, what each anti-detect tool leaks, and the durable signals. -->

# Findings

What Kitsune has actually measured, running each evader through the live edge → detector. The thesis
holds: **incoherence across layers, not any single bad signal, is what survives anti-detect tooling.**

## The arms-race ladder

Each rung defeats the rung below; the detector answers each with a new cross-layer check.

| Evader | Class | Live verdict | What betrays it |
| --- | --- | --- | --- |
| `vanilla` (httpx) | scripted HTTP | `bot` | no browser layer at all; datacenter ASN |
| `stealth-naive` (Playwright) | headless Chromium | `bot` | `navigator.webdriver`, headless UA, no `window.chrome` |
| `stealth-patched` / `full-stealth` | JS-patched stealth | `bot` | software WebGL, permissions anomaly, plugin/UA incoherence |
| `spoof-ua` | UA forgery on Chromium | `bot` | Firefox UA on a Chromium engine — `vendor`/`productSub`/render contradict the UA |
| `patchright` | CDP-patched Playwright | `bot` | removes the *automation* surface, but the headless **environment** fingerprint remains |
| `nodriver` | undetected-chromedriver heir | `bot` (0.94) | same: no webdriver flag, but headless-container environment betrays it |
| **`camoufox`** (headless) | **engine-level (C++) spoof** | **`bot` (0.86)** | **coherent JS layer — leaks via absent OS capabilities (WebGL2, TTS voices, media devices)** |
| **`camoufox-headful`** (Xvfb) | **engine-level, headful** | **`bot` (0.955)** | **gains WebGL2, but its renderer string is a placeholder; no TTS voices; no media devices** |

**Takeaway for the chromium tools:** removing the automation/webdriver surface does nothing for the
durable signal. Every Chromium-based tool runs headless Chromium in a container, and the *environment*
fingerprint (software WebGL, missing GPU, absent `window.chrome` surface) gives it away regardless of
how thoroughly the webdriver flag is hidden.

### The `Runtime.enable` CDP leak (the current chromium frontier)

The #1 headless-Chromium automation tell in current (2024-25) research: Playwright/Puppeteer enable the
CDP **`Runtime.enable`** domain, which makes the browser *eagerly serialize* console arguments for the
inspector. `br.cdp_runtime_enabled` exploits it — log an `Error` whose `stack` is a getter; the getter
fires only when a CDP client is serializing it. Validated live:

- **stealth-naive** (plain Playwright) → **fires** (`automation:6`). The CDP automation is caught.
- **patchright** (drop-in that patches `Runtime.enable`) → **does not fire** (`automation:4`). patchright's
  entire value-add is now *visible and quantified* in the detector — it zeroes out exactly this tell plus
  `webdriver`, where plain Playwright trips both.
- **rebrowser-playwright** (`REBROWSER_PATCHES_RUNTIME_FIX_MODE=addBinding`) → **does not fire**
  (`automation:5`). A *surgical* fix: it closes exactly the `Runtime.enable` leak (validating both the
  detection and rebrowser's claim) but leaves `navigator.webdriver`, the `HeadlessChrome` UA token, and
  `window.chrome` unpatched — unlike patchright's broader stealth.
- **nodriver** (undetected-chromedriver successor, "minimal CDP footprint") → **does not fire**
  (`automation:2`, the lowest of all CDP tools). Its claim **holds against the SOTA detection**: it avoids
  *both* `Runtime.enable` and `navigator.webdriver`. It is the most thorough on the automation *surface*
  — but it still ships a `HeadlessChrome` UA (`headless_ua`) and no `window.chrome.runtime`
  (`chrome_runtime_missing`), and is `bot` on the environment floor. Real-Chrome nodriver is also *less*
  stripped than Playwright's Chromium (`environment:3` vs `6`).

The three tools form a clean gradient of patch coverage — `automation` tells 6 → 5 → 4 (plain →
rebrowser → patchright) — yet **all three remain `bot`** on `environment:6`. The detector now measures
precisely which automation tells a given tool closes, while confirming the headless environment is the
floor none of them escape. (Setup yak-shave: the unpinned `rebrowser-playwright`/`patchright` drop-ins
each pull a different Playwright-core/Chromium revision; pin `rebrowser-playwright@1.48.2` to the base
image's Chromium-1140.)

## Behavioral biometrics is the weakest layer (`HUMAN_MOUSE=1`)

The behavioral motion rules (`bh.path_too_straight` >0.97, `bh.uniform_velocity` <0.08,
`bh.input_entropy_floor` <0.15) only catch *degenerate* input — a perfectly straight, constant-speed
move, or none at all. Measured against two evader mouse generators:

| Mouse | entropy | straightness | velocity CV | behavioral tells |
| --- | --- | --- | --- | --- |
| naive (sine wave) | 0.58 | 0.42 | 0.41 | none |
| human (`HUMAN_MOUSE=1`: Bézier + ease-in-out + jitter + variable timing) | 0.87 | 0.29 | 1.01 | none |

Even the *naive* path clears every threshold; the human generator clears them by a wider margin with
more human-like statistics. So behavioral motion thresholds are **trivially evaded** by any non-degenerate
motion — they catch a lazy `mouse.move(x, y)` straight line, nothing more. And tightening them is unsafe:
real human motion varies so widely that tighter thresholds would false-positive on people.

The `human-mouse` evader fully zeroes the behavioral column — yet is still `bot` on `automation:6` +
`environment:6` (it is naive Playwright Chromium). **Behavioral is the first layer to fall**, and defeating
it changes no verdict. This is why the durable signals are environment and coordination, not behaviour —
behavioral biometrics needs sophisticated sequence/biomechanics models, not static thresholds, to matter.

**Keystroke dynamics is the one exception that bites.** `bh.keystroke_entropy_floor` (the inter-key
interval entropy) is *not* as easily evaded as the mouse thresholds: a naive `page.keyboard.type` at a
fixed delay collapses to ~0 interval entropy and **fires** (`stealth-naive`, `behavioral:1`), because
fixed-delay typing is exactly what a form-filling bot does. Only genuinely *variable* digraph latencies
(measured 0.975 vs the 0.15 floor) evade it. So keystroke timing is a meaningful tell against the common
case (uniform automated typing) — where mouse-straightness is not (even a sine wave clears it). It still
falls to a bot that bothers to randomize key timing, but it raises the bar more than the mouse rules do.

## The baseline control — separating spoofing from a stripped environment

A detector that only fires on *headless-environment* tells is not detecting anti-detect spoofing — it is
detecting headless. To keep ourselves honest we run a **control group**: stock Playwright Firefox
(`KS_BASELINE=1` — Camoufox's exact engine, with **no** spoofing) through the same pipeline, and classify
every rule by what *kind* of tell it is (`category` in the registry; carried on each verdict
contradiction). Scoring the corpus by class (`docs/matrix.md`):

| Evader | coherence | artifact | automation | environment |
| --- | --- | --- | --- | --- |
| `baseline-firefox` (stock, no spoof) | 0 | 0 | 1 | 5 |
| `camoufox` (headless) | 1 | 0 | 0 | 3 |
| `camoufox-headful` | 0 | 1 | 0 | 2 |
| `spoof-ua` / `stealth-patched` | 1 | 0 | 2–3 | 2 |

- **`environment`** (no WebGL2, no TTS voices, no media devices, empty mimeTypes/plugins) and
  **`automation`** (`navigator.webdriver`) tells fire on the **stock baseline too** — they flag a
  stripped/automated environment, not spoofing. They are valid bot signals (bots run headless) but are
  *not* the thesis.
- **`coherence`** (cross-vector contradiction, e.g. `macos_dpr1`) and **`artifact`** (anti-detect
  implementation flaw, e.g. `webgl_renderer_artifact`) tells fire **only on a spoofing tool**, never on
  the baseline. These are the genuine anti-detect catches.

So Camoufox's whole achievement is visible in one row: it zeroes out the `automation` column (engine-level
`webdriver=false`) that catches stock Firefox — but it cannot avoid leaving a `coherence`/`artifact` tell.
And the honest frontier is also visible: most of Camoufox's current catch is still `environment`; a
headful deployment on real hardware would zero those out, leaving only the one or two coherence/artifact
tells. That residue is exactly what the white-box, source-driven detections target.

## Camoufox is the frontier

Camoufox spoofs at the engine level (C++), not via injected JS, so its lies are internally coherent in
ways patched-Chromium tools cannot match:

- **navigator.* coherence** — `platform`, `oscpu`, `vendor`, `userAgent`, `productSub`, render engine all
  agree on one OS/browser. The whole v0.7–0.10 OS-coherence battery (`navplatform_vs_ua`,
  `oscpu_vs_ua`, `vendor_vs_ua`, `productsub_vs_ua`) finds nothing — every value is consistent.
- **Per-launch randomization** — OS and hardware vary per instance (Windows/macOS, 8/12/32 cores) so no
  two instances look alike at the JS layer.
- **Font-metric spoofing (confirmed 2026-06-18)** — Camoufox spoofs Canvas `measureText` font metrics to
  match its claimed OS. An instance claiming macOS returns macOS-signature font widths (Helvetica Neue,
  Menlo, …) despite running on a Linux container, so the classic CreepJS/fingerprintjs **font-OS probe
  (`br.font_os_vs_ua`) is defeated** — the measured font OS coherently matches the claimed platform.
- **Device/media coherence (confirmed 2026-06-18)** — Camoufox keeps the CSS `matchMedia` view of the
  device consistent with the JS-API view: the v0.12.0 cross-API battery (`screen_avail_invalid`,
  `color_depth_anomaly`, `devicepixelratio_anomaly`, `hover_none_desktop`, `pointer_touch_incoherent`)
  finds nothing on Camoufox. These rules still catch chromium tools that patch one surface but not both.

**The per-session leaks that remain are OS *capabilities* a headless Linux container cannot fake**, not
fingerprint values (which Camoufox spoofs coherently):

- **`br.webgl2_missing`** — headless Camoufox exposes no WebGL2 context, where a real desktop does.
- **`br.voices_empty`** (confirmed 2026-06-18) — `speechSynthesis.getVoices()` is empty: a container has
  no TTS engine, but a real macOS/Windows desktop ships OS voices (Apple / Microsoft). Camoufox spoofs
  the *navigator* perfectly but cannot conjure an OS speech stack. (`br.voice_os_vs_ua` further flags a
  voice set whose OS contradicts the claimed platform, e.g. espeak/Linux voices under a Windows UA.)

Together these push a single coherent Camoufox instance to **`bot` 0.70** — the engine-level spoof that
once evaded every per-session rule is now caught per-session. The pattern: stop chasing spoofable
*values* and probe *capabilities the deployment environment lacks* (GPU, TTS).

**Spoof-specific tells that survive a headful, real-hardware deployment** (these do *not* fire on the
no-spoof baseline, so they are not headless artifacts — a macOS-draw Camoufox trips all three):

- `macos_dpr1` (coherence) — devicePixelRatio pinned to 1.0 on a Retina-implying macOS UA.
- `font_mac_internal` (artifact) — bundled dot-prefixed macOS system fonts are web-measurable.
- `webrtc_unavailable` (artifact) — **Camoufox disables WebRTC entirely** (no ICE candidates) to prevent
  the real-IP leak. Confirmed live: it fires on Camoufox but *not* on stock headless Firefox, which
  gathers candidates in the same container — so WebRTC absence is a deliberate anti-detect choice, itself
  the tell.

The no-win is now closed on both sides by a genuine **cross-layer** rule, `net.webrtc_ip_vs_observed`:
the edge emits the **observed connection IP** (`network.observed_ip`, the address the TLS connection came
from) and the collector reports the **WebRTC STUN public IP** (`browser.webrtc_public_ip`). When they
disagree — HTTP routed through a residential proxy while WebRTC leaks the real datacenter IP — the rule
fires (the canonical proxied-bot/residential-proxy tell, central to bots/DDoS). So an evader that *keeps*
WebRTC risks the cross-layer IP mismatch, and one that *disables* it trips `webrtc_unavailable`. This is
the first rule that correlates a signal the **edge** observed at the network layer with one the
**browser** reported — the cross-layer thesis in its purest form. (It needs a real proxy scenario to
trigger live; validated by unit tests, and it correctly does not fire on a direct connection where the
two IPs match.)

### The headful experiment — keeping the capability-probe honest

`webgl2_missing` could be just an artifact of running Camoufox **headless in a minimal container**, not a
flaw in its spoofing. So we ran it **headful in a virtual display** (`KS_HEADFUL=1` → `headless="virtual"`,
Xvfb) and re-measured (corpus: `camoufox-headful`):

- **WebGL2 leak closes** — headful Camoufox gets a software (llvmpipe) WebGL2 context, so `webgl2_missing`
  no longer fires. And `webgl_software` does *not* fire either: Camoufox spoofs the renderer string to a
  plausible GPU. Confirmed: the WebGL2 tell was a headless-deployment artifact, not a spoofing flaw.
- **TTS-voice leak persists** — `voices_empty` still fires; the audio/TTS stack is absent regardless of
  display. The capability-probe pattern survives going headful here.
- **New tell — the renderer-spoofing artifact.** Headful Camoufox reports a WebGL renderer of
  `"Intel(R) HD Graphics 400, or similar"`. No real GPU driver appends `", or similar"` — it is how
  Camoufox labels its randomized GPU pick. `br.webgl_renderer_artifact` catches this implementation flaw
  in the anti-detect tool's *own* spoofer, working precisely *because* the browser is headful (a real GL
  context exposes the spoofed string). Headful Camoufox is caught at **`bot` 0.90** (voices + artifact).

Lesson: each capability tell (`webgl2_missing`) can be a deployment artifact, falsifiable by a more
complete environment — but the anti-detect tool's own spoofing leaves implementation fingerprints
(`, or similar`) that betray it regardless. And a determined adversary closing every per-session tell
still cannot escape **coordination** (below), which is the backstop.

### Red-teaming the detector — a hardened Camoufox (`KS_HARDENED=1`)

The arms race in action: use Kitsune's own findings to harden the evader, via Camoufox's config, then
measure what survives. Levers applied: `os="windows"` (avoid the macOS-only tells), `block_webrtc=False`
(re-enable WebRTC), and an attempt at a clean `webgl_config`.

| Camoufox | coherence | artifact | environment | verdict |
| --- | --- | --- | --- | --- |
| default (macOS draw) | 1 (`macos_dpr1`) | 2 (`font_mac_internal`, `webrtc_unavailable`) | 3 | `bot` 0.92 |
| **hardened** (Windows-pinned) | **0** | **1** (`webrtc_unavailable`) | 3 | `bot` 0.93 |

Hardening **worked** for the OS-specific tells — pinning Windows removed `macos_dpr1` and
`font_mac_internal` (they are macOS-draw artifacts). But two tells proved **not config-fixable**:

- **`webgl_renderer_artifact`** — `webgl_config` can only *pick from* Camoufox's `webgl_data.db`, and
  **every renderer row in it carries the `", or similar"` suffix**. The artifact is baked into the data;
  a user cannot supply a clean renderer. (Headful-only, since headless exposes no WebGL2 context.)
- **`webrtc_unavailable`** — `block_webrtc=False` did not restore candidate gathering in our run, so the
  WebRTC tell persisted.

So even a maximally config-hardened Camoufox is still `bot` per-session — reduced from three
spoof-specific catches to one, but not zero — on top of the environment floor. The irreducible tell is
the renderer artifact: it is in Camoufox's shipped data, fixable only by patching the tool itself.

### The capstone — maximal stealth on both engines hits the same floor

Running the most-evasive build of each engine through the detector (`MAX_STEALTH=1` is patchright + a
coherent Linux-Chrome UA + human-mouse motion; `camoufox-hardened` is the Camoufox config red-team):

| Evader | coherence | artifact | automation | environment | verdict |
| --- | --- | --- | --- | --- |
| `baseline-firefox` (no spoof) | 0 | 0 | 1 | 5 | `bot` |
| `camoufox-hardened` (max Firefox stealth) | 0 | 1 | 0 | 3 | `bot` |
| `max-stealth` (max chromium stealth) | 0 | 0 | 4 | 6 | `bot` |

`max-stealth` shows every layer of evasion *working*: the Linux-Chrome UA removes `headless_ua`, the
human-mouse motion zeroes the behavioral column, and patchright closes `Runtime.enable` + `webdriver`.
Yet it is still `bot` — caught by the **environment floor** (`webgl_software`, `no_plugins`,
`media_devices_empty`, `voices_empty`, `mimetypes_empty`, `no_pdfviewer`) plus the residual automation
surface Chromium cannot fully hide. Camoufox-hardened closes *more* of the environment (engine-level
spoofing, fewer Chrome-specific strip tells) but cannot shed its one artifact.

**Both engines, maximally stealthed, converge on the same conclusion:** per-session evasion is a game of
attrition the evader loses — the headless *environment* is the irreducible floor, and beneath even that,
**coordination** is the backstop a single perfect instance cannot escape. That is the thesis, end to end.

### White-box analysis — reading Camoufox's source

Camoufox is open source, so we do not have to probe it as a black box. Reading the installed `camoufox`
package (it generates the fingerprint config the patched Firefox consumes) turns guesswork into precise,
provable detection:

- **`webgl/webgl_data.db`** — every renderer in the table is stored with a `", or similar"` suffix
  (`'Apple M1, or similar'`, `'ANGLE (NVIDIA, … Direct3D11 vs_5_0 ps_5_0), or similar'`). So
  `br.webgl_renderer_artifact` is not catching one observed string — it catches **every** Camoufox WebGL
  fingerprint *by construction*. The source proves the detection is comprehensive, not anecdotal.
- **`browserforge.yml`** (the cast map from Browserforge fingerprints → Camoufox config) documents what
  Camoufox **cannot** spoof, in its own comments:
  - `# Unsupported: videoCodecs, audioCodecs, pluginsData, multimediaDevices` — media-device enumeration
    is not spoofed. `br.media_devices_empty` exploits this directly: a headless container enumerates no
    devices, where a real desktop always has at least a default audio endpoint. **Confirmed live** — it
    fires on both headless and headful Camoufox (pushing them to `bot` 0.86 / 0.955).
  - `# devicePixelRatio … Any value other than 1.0 is suspicious` — Camoufox is pinned to dPR 1.0, so it
    cannot present a coherent Retina/high-DPI profile. `br.macos_dpr1` exploits this: **confirmed live**,
    it fires on exactly the launches where Camoufox draws a macOS platform (a modern Mac is Retina, dPR 2)
    and not on its Windows draws — a Camoufox-specific coherence tell, not a generic headless one.
  - `# Never override productSub`, `pdfViewerEnabled … kept to True` — further fixed values.
- **`addons.py` — uBlock Origin is a default addon** (`DefaultAddons.UBO`, added unconditionally in
  `utils.py` unless `exclude_addons` is passed). So a stock Camoufox runs a content blocker.
  `br.adblock_present` (ad-bait cosmetic detection) targets this — kept *experimental*: it is weak alone
  (many humans run adblockers) and did not fire in our short isolated sessions (fresh uBO compiles its
  filter lists slower than the ~3s capture window), but it is a documented default worth flagging.
- **`fonts.json` — fixed per-OS font lists** (win 107, mac 573, lin 134). Two leads; one validated:
  - The mac list bundles **49 dot-prefixed system fonts** (`.Aqua Kana`, `.Apple Color Emoji UI`) that a
    real macOS browser never exposes to `measureText`. `br.font_mac_internal` — **confirmed live** on
    Camoufox's macOS draws — an `artifact` tell (Camoufox over-exposed its bundled list) that works
    headful (font metrics need no display). With `macos_dpr1` it gives a macOS-draw Camoufox *two*
    spoof-specific catches independent of the environment tells.
  - Arimo/Cousine/Tinos are Linux-only in the lists, so a leak under a non-Linux UA would betray the
    container — but `br.font_linux_leak` did **not** fire: Camoufox's font spoofing is complete, the
    container fonts do not leak. Kept experimental (it would still catch a naive non-font-spoofing tool).
- **No audio handling in the package** — Camoufox does *not* farble the AudioContext. So `br.audio_noise`
  (per-render perturbation) correctly does **not** fire on Camoufox; it is reserved for farbling browsers
  (Brave) and tools that randomize audio per read. Reading the source told us this *before* testing,
  saving a blind-probing cycle.

The method generalizes: for any open-source anti-detect tool, read its spoof map, detect the documented
**gaps** (capabilities it leaves real) and its **construction artifacts** (placeholder strings, fixed
values) — far stronger than black-box probing.

## The durable signal: coordination, not the instance

A *single* Camoufox session can be made arbitrarily coherent. A *fleet* cannot hide that it shares an
identity below the spoofing layer:

- All instances of a fleet share one **JA4 cipher-suite prefix** (JA4_a + JA4_b) — the TLS handshake is
  the engine's, and anti-detect tools spoof JS, not the cipher suites. (JA3 is not stable across GREASE.)
- The instances deliberately **randomize their JS identity** (hardware, platform) to look like distinct
  users.
- **Camoufox also randomizes JA4_c (confirmed 2026-06-18)** — the extensions + signature-algorithms
  component of JA4 varies per launch (e.g. `…_3cbfd9057e0d` vs `…_e6dcd7ae0a9e` under an identical
  `t13d1717h2_5b57614c22b0` prefix). So the *full* JA4 is not fleet-stable; the fleet key must be the
  prefix. And because JA4 deliberately **sorts** extensions to defeat Chrome's order-shuffling, a varying
  JA4_c means the actual extension/sig-alg *set* is being manipulated — itself an anti-detect TLS tell.

The coordination scorer keys on the JA4 prefix and grades on three signals, any of which is enough to
reach `fleet`: the **JS-divergence paradox**, **JA4_c divergence** (shared cipher prefix but per-launch
extension randomization), and **timing lockstep**, scaled by volume. This is robust to *both* of
Camoufox's randomizations — randomizing JS feeds the JS paradox, randomizing JA4_c feeds the TLS tell.
Even when a run's JS traits collide by chance (all instances draw the same hardware/platform), the JA4_c
divergence alone catches the fleet.

`harness/coordination.py` grades a JA4 cluster on three independent coordination signals:

1. **JS-divergence paradox** — TLS-identical but JS-divergent. A genuine same-build cohort that shares a
   JA4 also shares its JS identity; only a spoofing fleet shows one TLS fingerprint under many JS
   identities. This is the primary discriminator (a homogeneous JA4 cluster never reaches `fleet`).
2. **Timing lockstep** — fleet instances launch together. Members sharing a JA4 that all arrive inside a
   2-minute window are synchronized; organic same-JA4 users are spread over hours.
3. **Volume** — more members in the cluster raises confidence.

The live Camoufox fleet scores **`fleet` 1.00**: shared JA4, JS divergent across all three instances
(hardware 8/12/32, platform Windows/macOS), and all three arriving within 20 seconds.

This is the signal that matters for the bots/DDoS domain: an attacker fielding thousands of coherent
anti-detect browsers still routes them through a shared engine/TLS stack, and the coordination is visible
in aggregate even when every instance is individually perfect.

### Residential-proxy fleets — turning IP diversity into a tell

The modern botnet defeats IP-based defenses (rate limits, datacenter-ASN rules) by exiting each bot
through a *different residential proxy* — so the source IPs look like distinct, ordinary users. The
coordination scorer adds two IP-topology signals that make that diversity self-incriminating
(`docs/coordination-proxy.md`, scored from a synthetic fleet since the lab has no proxies to capture):

- **Residential-proxy pattern** — a *confirmed* spoofing fleet (JS paradox or JA4_c divergence) that is
  *also* spread across many distinct `network.observed_ip` values. IP diversity alone is the null
  hypothesis (many real users share a JA4 prefix), so it only escalates once a spoofing tell is already
  present — at which point the spread reveals a distributed botnet rather than one misconfigured client.
- **Same-origin behind proxies** — diverse observed (proxy) IPs but a single shared
  `browser.webrtc_public_ip`: the proxies are fronting *one* real origin, leaked by WebRTC. Very hard to
  explain innocently (it cross-links the cross-layer WebRTC signal with the fleet view).

A synthetic residential-proxy Camoufox fleet (3 nodes, distinct residential exit IPs, one real datacenter
origin) scores **`fleet` 1.00** on *all six* signals at once — JS paradox, JA4_c divergence, timing
lockstep, volume, residential-proxy spread, and same-origin WebRTC IP. The lesson for the DDoS frontier:
distributing a botnet across residential proxies hides it from per-IP defenses but not from coordination
analysis — the shared engine identity and the converging real origin betray the fleet regardless.

**Confidence vs severity.** The fleet `score` answers *is this coordinated?* — and a confirmed fleet
maxes it whether it is 3 nodes or 3,000. For operational triage the verdict also reports a **severity**
derived from scale and rate, independent of the score: aggregate `request_volume` and the session
`arrival_rate_per_min` (burst rate) tier the fleet `moderate` / `high` / `critical`. A 3-node demo fleet
is `moderate`; a paradox fleet of dozens arriving in a tight window is `critical` — the difference between
a curiosity and an active attack, which the binary fleet label alone cannot convey.

## Testing strategy (efficiency)

Re-running the seven known-caught evaders every iteration teaches nothing. Testing is tiered:

- **Frontier tier** (`scripts/frontier.sh`, every iteration) — only the evaders that still beat
  per-session detection: Camoufox single + a Camoufox fleet. Fast; this is where detection still loses.
- **Regression tier** (`scripts/live_scoreboard.sh`, sparse) — the full known-caught fleet, run
  occasionally to confirm no regression.

### Cutting single-Camoufox iteration time

A live Camoufox capture costs ~10-13s, **dominated by browser cold-start** (the fixed collector/runner
waits are ~3s and lost in launch variance). Three levers, in order of impact:

1. **Don't recapture for rule-only changes.** A live capture is only needed when the *collector*
   (emitted signals) changes. For *rule* edits (`registry.yaml`), `python -m kitsune_harness.corpus
   corpus/sessions` re-scores the recorded session with the current ruleset in **~0.3s, no browser**.
2. **Amortize the cold-start** for repeated single captures: `KS_REPEAT=N` captures N sessions from one
   browser launch (~5.5s/capture vs ~12s). *Not* for fleets — Camoufox randomizes per *launch*, so
   contexts of one launch share a fingerprint and show no cross-instance divergence.
3. **Skip the fixed waits** with `KS_FAST=1`: an event-driven, detection-only capture (waits on
   `body[data-ks=sent]`, no mouse simulation). In fast mode the collector omits the behavioral layer so
   the *absence* of simulated input is not mis-scored as bot-like — the verdict reflects the fingerprint.
