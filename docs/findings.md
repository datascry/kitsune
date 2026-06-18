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

**zendriver — the maintained successor — closes one more automation tell, same floor.** nodriver is now
effectively unmaintained; `zendriver` forked it and is the tool the community currently reaches for, so it
is the right frontier sample. Evaluated head-to-head against nodriver on the refreshed corpus, the diff is
exactly one tell each way: zendriver no longer leaks `br.headless_ua` (it strips the `HeadlessChrome` UA
token nodriver still ships), while it trips `br.webrtc_unavailable` where nodriver did not. The other
seven environment tells are shared. So zendriver is marginally stealthier on the *automation surface* — it
closes the UA token, on top of already avoiding `navigator.webdriver` and the `Runtime.enable` leak like
its predecessor — yet it lands on the identical `environment` floor (software WebGL, no TTS voices, empty
media devices, missing `window.chrome.runtime`) and scores `bot` at 0.998. The newest recommended CDP tool
moves the automation needle by one and changes no verdict: the floor, not the automation surface, is what
convicts — and it is exactly where these tools cannot follow without real hardware.

**selenium-driverless — the adversarial test of the `Runtime.enable` rule, and an honest result.**
`selenium-driverless` is a different family (a Selenium-style API with no chromedriver) whose headline
claim is that it runs page interaction in *isolated worlds* specifically to avoid the `Runtime.enable`
leak. That makes it the sharpest available test of `br.cdp_runtime_enabled`, the SOTA detection — so the
honest question is whether the rule survives a tool built to defeat it. It does not: captured live,
`br.cdp_runtime_enabled` **does not fire**, and neither does any `webdriver` tell. The claim holds; the
strongest single automation signal is genuinely evaded, across a second tool family beyond the patched-
Playwright drop-ins. And yet the verdict is `bot` at 0.999 — selenium-driverless still ships a
`HeadlessChrome` UA and lands on the same `environment` floor (software WebGL, no voices, empty media
devices, no `window.chrome.runtime`) as everything else. This is the most important confirmation in the
lab: a tool that *wins* the automation-surface arms race against our best CDP rule changes the score by
nothing, because the conviction never depended on that rule. Stacking automation tells is a treadmill;
the environment floor is the wall. (Container note: like undetected-chromedriver it needs
`--disable-dev-shm-usage` and an explicit `--headless=new` or Chrome never connects.)

**pydoll closes the survey — the third independent evasion of `Runtime.enable`, same wall.** `pydoll` is
the last distinct family: async, CDP-native, no webdriver, marketed for Turnstile/Cloudflare bypass.
Captured live it is the *third* tool — after selenium-driverless and the patched-Playwright drop-ins — to
defeat `br.cdp_runtime_enabled` (does not fire) and ship no `webdriver` tell, and it scores `bot` at 0.999
on the identical environment floor. Three unrelated codebases independently beating the SOTA automation
signal while none escapes the floor is the strongest evidence the lab can offer that the conclusion is
*structural*, not an artifact of one tool: page automation can be made invisible, but a headless browser
on no real GPU, with no OS speech voices and no enumerable media devices, cannot be made to look like a
person's machine without *being* one. That is the finding the whole survey converges on, and pydoll is
where it stops being a claim about specific tools and becomes a claim about the category.

### Survey coverage — every open-source family, one conclusion

The evaluated fleet now spans every open-source anti-detect family: scripted HTTP (vanilla/httpx),
Playwright stealth (naive → max-stealth, spoof-ua, human-mouse), CDP-leak patch drop-ins (patchright,
rebrowser), CDP-native automation (nodriver, zendriver, pydoll), isolated-world Selenium (undetected,
selenium-driverless), engine-level coherent spoof (Camoufox ×3 modes), and privacy/farbling browsers
(Brave; Tor/Mullvad RFP). Every one is `bot`. The tools differ enormously on the *automation surface* —
some leak `webdriver` and `Runtime.enable`, the best leak neither — but the verdict is decided below that
surface, on the environment floor and (for coordinated fleets) on cross-instance incoherence. Tool
breadth has reached the point of diminishing returns: new captures now confirm the structural conclusion
rather than testing it.

### Red-teaming the floor — `FLOOR_SPOOF`, and why presence can't be faked for free

A fair objection: if every tool is convicted on the *environment floor*, are those checks a real wall or
just absence-detectors that fold the moment someone fakes presence? `FLOOR_SPOOF` tests it directly. It is
patchright (clean CDP stealth) on a coherent Linux-Chrome UA, plus an init script that overrides
`speechSynthesis.getVoices` (returning Linux-coherent espeak-style voices, so `br.voice_os_vs_ua` stays
quiet) and `navigator.mediaDevices.enumerateDevices` (returning present-but-unlabelled devices). The first
result was instructive: **both `br.voices_empty` and `br.media_devices_empty` stopped firing** — the
floor's *presence* checks are indeed defeated by faking presence, and no coherence rule caught the fake
data. So the absence-detectors alone are not a wall.

But faking presence is not free: you can only do it by *replacing* the native method, and the replacement
betrays itself. The fix added `getVoices` and `enumerateDevices` to the `toString`-tamper probe (the same
mechanism that already catches WebGL/`webdriver` overrides — a real browser's methods always report
`[native code]`). Re-run, `br.tostring_tampered` **fires**, and the spoof is caught — not for the absent
floor, but for the tampering required to fake it. This is the coherence thesis in a single exchange: the
naive bot is caught for what it *lacks*; the sophisticated bot that supplies what it lacks is caught for
the *act of supplying it*. The evader stays `bot` either way (still leaking `mimetypes_empty`,
`no_plugins`, `permissions_anomaly`, software WebGL, plus the behavioral and webdriver-patch tells), but
the lesson is the durable one: there is no free lunch in faking environment presence from a headless
browser — absence is a tell, and the only cure for absence is tampering, which is also a tell.

The follow-up round made the same point on *properties* rather than *methods*, and showed the detector
already half-knew the trick. Extending `FLOOR_SPOOF` to also fake the PDF floor — `pdfViewerEnabled` and
`mimeTypes`, defined on the navigator instance — duly silenced `br.chrome_no_pdfviewer` and
`br.mimetypes_empty`, and at first nothing replaced them. But `br.plugins_spoofed` already encoded the
right idea for one property: `navigator.plugins` is a prototype-inherited accessor on a real browser, so
an *own* property on the instance is itself the lie (CreepJS-style location detection). The fix just
generalised that one check to the other prototype properties a floor-spoofer redefines —
`br.nav_property_spoofed` now fires when `pdfViewerEnabled` or `mimeTypes` appears as an own property.
Re-run, the PDF fakes are caught not for the value they assert but for living in the wrong place on the
object. Two rounds, two mechanisms — non-native `toString` for replaced *methods*, own-property descriptors
for replaced *properties* — and the same conclusion holds: every way to manufacture a missing capability
leaves a structural fingerprint of the manufacturing.

Round three is the sharpest, because the obvious coherence fix would have *failed*. `FLOOR_SPOOF` next
faked `Notification.permission`, claiming `"default"` to beat `br.notification_denied`. That also silenced
`br.permissions_anomaly` — and not by luck the detector could punish: headless Chrome reports
`Notification.permission === "denied"` while the Permissions API query returns `"prompt"` (that mismatch
*is* the original anomaly), so faking `"default"` (which maps to `"prompt"`) makes the two views
*coherent*. A bidirectional permission-vs-query check would see agreement and stay silent; the spoof wins
on coherence. The only thing it cannot hide is that `Notification.permission` is a native static getter
and it replaced it — so `br.notification_getter_tampered` reads the getter's `toString` and fires on the
non-native function, exactly as `webdriver_getter_tampered` does for the prototype webdriver patch. The
lesson sharpens: it is not that spoofs create incoherence (this one removed it) — it is that the *act of
overriding a native member is itself observable*, whether the member is a method, a property, or a getter,
and no amount of making the faked value coherent erases the fingerprint of having faked it.

### CSP bypass — a tell the patches themselves admit they can't fix

Reading the canonical CDP-detection catalog (`rebrowser-bot-detector`) against Kitsune's coverage, every
vector it enumerates was already caught — `runtimeEnableLeak`, `navigatorWebdriver`, the `HeadlessChrome`
UA — *except one*: **`bypassCsp`**. Playwright and Puppeteer scrapers routinely call `setBypassCSP(true)`
so their injected scripts run on CSP-protected pages; doing so silently disables CSP enforcement for the
whole context. A real browser *never* does this. The detector now serves its page with a deliberately
strict `img-src 'none'` (permissive `default-src *` for everything the collector actually uses, so no
other signal is perturbed) and the collector loads a tiny data-URI image: a real browser fires
`securitypolicyviolation` and the probe stays quiet, while a context that bypassed CSP loads it silently —
`br.csp_bypassed` (automation, 0.6). The listener is attached before the probe triggers, so there is no
ordering race. What makes this the cutting edge: rebrowser's own documentation lists `bypassCsp` as **not
addressed by the patches** ("restructure your code to comply with CSP") — so unlike `Runtime.enable`,
there is no stealth drop-in that closes it. A scraper that needs script injection on a CSP page must
choose between bypassing CSP (and tripping this) or not injecting at all.

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

**The motion-*statistics* arms race has a structural exit: coalesced events.** Tightening straightness or
velocity thresholds is a losing game — a bot can always shape its *path* to match human statistics. But
`PointerEvent.getCoalescedEvents()` exposes something the path cannot fake: real pointer hardware is
sampled faster than the browser dispatches `pointermove` (a 125 Hz+ mouse against a 60 Hz frame), so the
browser batches the intermediate samples and a real stream coalesces (length > 1) within a few dozen
moves. Synthetic movement injected through CDP `Input.dispatchMouseEvent` — the mechanism Playwright,
Puppeteer-extra, and the driverless/CDP-stealth tools use to draw a human-like Bézier curve — arrives one
discrete event at a time and *never* coalesces. `bh.synthetic_no_coalesced` fires when a pointer stream is
long enough to expect coalescing (≥20 moves) on an engine that supports it, yet none ever occurred. This
catches a bot that has already beaten every motion-statistics check, because the tell is in the *delivery*
of the events, not their geometry. It is weighted as a corroborator (0.45, suspicious-not-convict): a real
human on an unusual low-rate device might not coalesce, so it raises a flag rather than deciding alone —
but stacked with the environment and automation layers it removes the "I simulated perfect human motion"
escape hatch.

**Keystroke dynamics is the one exception that bites.** `bh.keystroke_entropy_floor` (the inter-key
interval entropy) is *not* as easily evaded as the mouse thresholds: a naive `page.keyboard.type` at a
fixed delay collapses to ~0 interval entropy and **fires** (`stealth-naive`, `behavioral:1`), because
fixed-delay typing is exactly what a form-filling bot does. Only genuinely *variable* digraph latencies
(measured 0.975 vs the 0.15 floor) evade it. So keystroke timing is a meaningful tell against the common
case (uniform automated typing) — where mouse-straightness is not (even a sine wave clears it). It still
falls to a bot that bothers to randomize key timing, but it raises the bar more than the mouse rules do.

## Precision — legitimate humans must not be flagged

Every other section is about *recall* (catching evaders). A detector that flags everything is useless, so
`tests/test_precision.py` asserts the other half: a panel of fully-coherent human profiles
(Windows Chrome, macOS Chrome Retina, Linux Firefox, plus two notorious edge cases) all score `human`.

Building it **surfaced two real false-positive surfaces** that recall testing never would have:

- **`br.maxtouch_desktop`** (maxTouchPoints > 0 on a desktop UA) flagged a **Windows 2-in-1 touch laptop**
  — an enormous, ordinary population. Retired: it is superseded by `br.pointer_touch_incoherent`, which
  is the *sound* version (it fires only when the CSS touch surface and the JS touch surface *disagree*,
  i.e. a spoof, not a real touchscreen).
- **`br.macos_dpr1`** (macOS UA + devicePixelRatio 1.0) flagged a **desktop Mac on a 1080p external
  monitor** (legitimately dPR 1.0). Kept — it is a real Camoufox tell — but its weight was cut to 0.3,
  *below* the suspicious threshold (0.35), so it can no longer flag a human on its own; it only
  corroborates inside a cluster of tells (Camoufox still trips it alongside `font_mac_internal`,
  `webrtc_unavailable`, etc. and stays `bot` 0.99).

A second pass added a **corporate VM/VDI** profile and caught a third: **`br.webgl_software`** (software
WebGL — SwiftShader/llvmpipe) flagged it `suspicious` 0.60 on its own. VM/VDI sessions have no passthrough
GPU and fall back to software rendering — a *large* enterprise population — yet software WebGL is also a
headless tell. Same fix: weight cut 0.6 → 0.3 (below threshold), so it corroborates with the *other*
headless tells a real VDI user does not have (no `voices_empty`, no `media_devices_empty`, …) but never
convicts a VM user alone. Recall intact: every chromium evader trips it *alongside* `webdriver`/`headless_ua`
and stays `bot`.

The lesson: a tell calibrated only against bots will fire on the long tail of unusual-but-legitimate human
configurations (touch laptops, external monitors, old displays, **VMs/VDI**). Precision testing is the only
thing that catches it, and the fix is either a *coherence* reformulation (touch) or a weight below the
action threshold so the signal corroborates without convicting alone (dPR, software WebGL). The pattern
that emerges: **environment tells must corroborate, not convict** — each has an innocent lone explanation,
but a real human almost never trips several at once, and noisy-or makes the combination decisive. Recall
was unaffected throughout — every evader still scores `bot`.

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

**Offline snapshot vs online stream.** `score_corpus` grades a static snapshot, but a production bots/DDoS
detector works **online**: sessions stream in, clusters form incrementally, and it alerts the moment a
cluster crosses the threshold — not after the attack is over. `FleetTracker.observe(name, session)` models
this: it re-scores only the affected JA4-prefix cluster per arrival and returns a verdict exactly when the
cluster *newly* becomes a `fleet` or escalates to a higher severity tier (so it alerts once, not on every
confirming member). Replayed over the residential-proxy fleet in arrival order, it alerts on the **second
arrival** — the instant the paradox becomes observable — rather than waiting for the third. That early,
edge-triggered alert is what lets a real defense act mid-attack instead of in post-mortem.

A production detector also **windows**: `FleetTracker(window_seconds=W)` only counts cluster members
within `W` seconds of the latest arrival, ageing out the rest. This is the difference between detecting a
*burst* and slowly accumulating unrelated same-browser users into a false fleet over hours — two paradox
nodes 10s apart alert; the same two 10 minutes apart never coexist in the window and do not. When a burst
ages out, the cluster's alert state resets, so a *fresh* burst on the same JA4 prefix re-alerts rather
than staying silent. Windowing is also what makes the `arrival_rate_per_min` severity meaningful: a true
current rate, not an all-time average diluted by history.

## The scripted-flood tier — three HTTP-header tells before any JS runs

The cheapest attack is also the most common at volume: a script (httpx/requests/curl/Go) that forges a
browser `User-Agent` and never runs a line of JavaScript. It is caught at the HTTP layer, before the
collector is even served, by three independent tells the edge reads off the request — and a real
volumetric flood trips all three at once (validated live against the `vanilla` httpx client wearing a
Chrome UA):

- **`net.no_js_execution`** — a network fingerprint with no browser layer at all: the collector never ran.
- **`net.sec_fetch_vs_ua`** — a modern-browser UA with no `Sec-Fetch-*` metadata headers, which every real
  browser sends on navigation.
- **`net.accept_encoding_vs_ua`** — a modern-browser UA whose `Accept-Encoding` omits Brotli. Every current
  browser advertises `br` (and now `zstd`) over HTTPS; httpx/requests default to `gzip, deflate`. It is an
  HTTP *compression* fingerprint, independent of the Sec-Fetch and TLS signals.

None of these requires JavaScript, a reference database, or even a complete TLS handshake to parse — they
are pure properties of the forged request, so the volumetric tier is convicted at the lowest cost the
detector has. The UA can be forged; the *shape of the HTTP request a real browser makes* cannot, not
without becoming a real browser.

…unless you make the shape perfectly. `curl-impersonate` (via `curl_cffi`) is the other end of the
scripted spectrum: it reproduces a real Chrome ClientHello (JA3/JA4), the Chrome HTTP/2 SETTINGS and
pseudo-header order, and the *full* browser header set — `Sec-Fetch-*`, `Sec-CH-UA(-Platform)`,
`Accept-Encoding: …br, zstd`. Captured live it does exactly what its design promises: **every HTTP-header
and cross-layer tell stays silent** — `sec_fetch_vs_ua`, `accept_encoding_vs_ua`, `ch_ua_vs_ua_browser`,
the h2 rules — because nothing it sends is incoherent. This is the useful negative result: it confirms
those rules are *precise*, firing on naive forgery (httpx) and not on a sophisticated client that sends a
correct request. And yet curl-impersonate is still `bot` (0.9) on a single rule: `net.no_js_execution`.
Perfect network mimicry buys a coherent network layer and nothing above it — there is no JS layer at all,
because there is no browser. It is the network-layer twin of the selenium-driverless result: a tool that
wins its own arms race completely is convicted on the axis it never entered. TLS/HTTP can be impersonated;
*executing the page* cannot be, by a thing that is not a browser.

## The HTTP/2 preface — a UA-spoof tell below the application layer

The TLS ClientHello (JA3/JA4) and the in-page JS fingerprint are the two layers an evader works hardest
to make coherent. Between them sits a third the application code never touches: the **HTTP/2 connection
preface**. Before the first request, an h2 client sends a SETTINGS frame, a connection-level
WINDOW_UPDATE, optionally PRIORITY frames, and then a HEADERS frame whose **pseudo-header order**
(`:method`/`:authority`/`:scheme`/`:path`) is fixed by the client stack. These are engine choices, not
content: Chromium emits the pseudo-headers `m,a,s,p`, Firefox `m,p,a,s`, Safari `m,s,p,a`, and the
SETTINGS values differ too (the Akamai *h2 fingerprint*, Black Hat EU 2017). A scripted client that
forges a `Chrome/…` User-Agent over a Go or Python h2 stack contradicts itself here — Chrome UA, non-Chrome
h2 — and the contradiction is invisible at the layers it spent effort spoofing.

The edge now captures this **live**. The bundled Go h2 server hides the preface and drops per-connection
context on its streams, so the edge serves ALPN `h2` through its own handler (`serveH2`): it tees the
decrypted preface through a frame parser (`fingerprint.ParsePreface`, built on `x/net/http2` + `hpack` to
recover pseudo-header order), threads both the ClientHello and the resulting h2 fingerprint into the
connection's base context, then replays the consumed bytes to `http2.Server.ServeConn` so the request is
served unharmed. Three rules consume the result: `net.h2_vs_ua_browser` (cross-layer — h2 engine vs UA
browser, so the incoherence weight applies) and `net.h2_vs_tls_browser` (within-network — h2 engine vs the
JA4 TLS engine). This closes the last *layer* gap: the edge now fingerprints the client at TLS, HTTP/2,
and JS simultaneously, and any two disagreeing is a tell no single-layer spoof can avoid.

The h2 fingerprint also carries an **internal** coherence check. The engine can be read two independent
ways from one preface: the pseudo-header order (`Browser()`) *and* the set of SETTINGS identifiers
(`SettingsBrowser()` — Chromium sends `{1,2,3,4,6}`, Firefox `{1,4,5}`, both stable and distinctive). A
tool that patched one facet to look like Chrome but left the other at its library default contradicts
*itself* within the single h2 fingerprint — `net.h2_settings_vs_order` fires before the TLS or JS layers
are even consulted. The classifier is deliberately conservative (only the two stable profiles are named;
everything else is `unknown` and emits no hint), so the rule fires solely on a real half-spoof and never
on a browser it simply doesn't recognise.

The capture-and-replay trick is the same one the edge already uses for the ClientHello (`peek.Conn`): read
the bytes you need to fingerprint, buffer them, and replay on `Read` so the wrapping server still sees a
complete connection. Parsing is best-effort — a malformed or truncated preface leaves the connection
served and simply carries no h2 signal, never breaking traffic to fingerprint it.

**Best-effort is not enough; the parsers are fuzz-hardened.** The edge fingerprints *adversarial* input —
`ParseClientHello` and `ParsePreface` run on raw bytes from arbitrary, possibly hostile clients, so a
panic in either is a denial-of-service on the detector edge, which matters doubly in a bots/DDoS context.
Both carry Go native fuzz targets (`FuzzParseClientHello`, `FuzzParsePreface`) seeded with valid and
malformed inputs; ~2.4M and ~4M executions respectively turned up no panic. The contract is explicit and
tested: on any byte string the parsers return an error, never crash — junk traffic costs the edge a failed
parse, not availability.

### Toward HTTP/2 Rapid Reset (CVE-2023-44487) — the DDoS frontier at the frame layer

The h2 preface fingerprint identifies *who* a client is; the frame *stream* reveals what it is *doing*.
The headline HTTP/2 DDoS technique — Rapid Reset — opens a stream with HEADERS and immediately cancels it
with RST_STREAM, over and over, doing per-request server work while never holding open streams against the
concurrency limit. It is the single most significant recent layer-7 DoS, and squarely in this lab's
bots-and-DDoS remit. The foundation lands here: `H2FrameScanner` consumes a *copy* of a connection's bytes
incrementally (across arbitrary Read boundaries — frame headers and payloads straddle TCP segments),
counts HEADERS and RST_STREAM frames by walking the 9-byte frame headers, and `RapidReset()` flags the
signature — RST_STREAM at flood scale (≥100) that roughly tracks the HEADERS count, which no real browser
ever produces. It is observe-only by construction: fed a copy, it cannot alter what the HTTP/2 server
reads, so a counting bug can never affect serving. Like the other adversarial parsers it is unit-tested
(including frames split across chunk boundaries) and fuzzed (~1.8M executions, no panic).

It is now wired: `serveH2` puts a `countingConn` between the preface conn and `http2.Server.ServeConn`,
teeing every byte the server reads into the scanner, and threads the scanner through the base context.
A per-request `ServeHTTP` then emits `net.h2_rapid_reset` (weight 0.9 — never a human) when the connection's
scanner crosses the flood threshold. The scoping is deliberate: Rapid Reset is *connection*-level abuse,
not a *session* fingerprint, so the signal is attached to the session that connection carries; an
anonymous pure flood with no completed request never reaches a handler and is left to a rate limiter,
which is its job. Two properties make this clean rather than a layering violation. First, it is
**complementary to mitigation, not a replacement**: the `x/net` HTTP/2 server already *defends* against
Rapid Reset (Go's CVE-2023-44487 patch caps and closes abusive connections) — that protects availability;
the detector's job is different, to *attribute* the abuse to a fingerprinted session so a repeat offender
is known, not merely disconnected. Second, the detection rides entirely on the observe-only tee and the
existing per-request signal path, so it adds a DoS-attribution signal without touching how connections are
served or mitigated. The wiring is unit-tested (the tee feeds the scanner and passes bytes through
unchanged; a rapid-reset-laden context makes `ServeHTTP` emit the signal); the rule fires in the engine.

**Validated live, against the actual attack.** `evaders/h2-rapid-reset` is a raw-framer CVE-2023-44487
client: it mints a session, floods 150 `HEADERS`+`RST_STREAM` pairs, then sends one final completing
request so a handler runs. The open question the unit tests could not answer was timing — does the
detection threshold fire *before* the `x/net` server's own mitigation closes the connection? The live run
settles it: all 150 resets land, the final request completes, and the session is scored `bot` (0.99) with
`net.h2_rapid_reset` *and* `net.no_js_execution` (a raw framer has no browser layer either). So the
conservative threshold (100) fires comfortably inside the server's tolerance window — detection and
mitigation compose rather than race. The flood session now lives in the corpus, so the rule is exercised
on recall, not only in unit tests. (Aside, and a lesson re-learned: the first cut of the raw-framer client
hung on a blocking `ReadFrame` with no deadline — adversarial *clients* need timeouts as much as
adversarial *servers* do.)

**The whole HTTP/2 DoS family, one scanner.** Rapid reset is one of a set of frame-level layer-7 DoS
techniques, and the scanner generalises to the rest at almost no cost — it already walks every frame
header, so counting three more types covers the family. `net.h2_continuation_flood` flags **CVE-2024-27316**
(the 2024 successor: an open HEADERS followed by an endless CONTINUATION stream that never sets
END_HEADERS, exhausting header-buffer memory), and `net.h2_control_flood` flags the 2019 control-frame
floods (**CVE-2019-9515** SETTINGS / **CVE-2019-9512** PING — spamming control frames to force ACK work).
The thresholds are conservative because a real connection sends ~0 CONTINUATION frames and a single
preface SETTINGS: 50 CONTINUATIONs or 100 control frames is unambiguous abuse. The CONTINUATION flood is
live-validated with a second mode of the raw-framer evader (`KS_MODE=continuation`): 150 empty
CONTINUATION frames, `net.h2_continuation_flood` fires, session `bot`, recorded into the corpus. One
observe-only scanner, fuzzed and threaded through the existing signal path, now covers rapid reset, the
CONTINUATION flood, and the control-frame floods — the layer-7 DoS surface an edge in a bots/DDoS context
is most expected to attribute.

### What live capture taught the SETTINGS classifier

Driving real browsers through the edge corrected the SETTINGS-profile classifier twice — a reminder that
fingerprint constants from blog posts drift, and only live traffic is ground truth. Two SETTINGS bits
that look like clean engine discriminators are not: **`ENABLE_PUSH(2)`** is sent (`=0`) by *both* modern
Chromium and Firefox since HTTP/2 server-push was deprecated (live Camoufox sends Firefox `{1,2,4,5}`, not
the textbook `{1,4,5}`), and **`MAX_CONCURRENT_STREAMS(3)`** is sent by headful Chrome but *omitted* by
headless (live `{1,2,4,6}` vs `{1,2,3,4,6}`). An early version of the classifier gated on both and so
silently failed to recognise real headless Chrome and real Camoufox. The stable discriminator is the pair
that genuinely partitions the two stacks: Chromium sends `MAX_HEADER_LIST_SIZE(6)` and no `MAX_FRAME_SIZE`,
Firefox sends `MAX_FRAME_SIZE(5)` and no header-list cap. Keying on `6-and-not-5` vs `5-and-not-6` is
robust across headful/headless and the push-deprecation change.

The Camoufox capture also settled the engine-level-spoof question at the network layer: its h2 fingerprint
is *fully coherent* Firefox — pseudo-order `m,p,a,s`, SETTINGS classifying firefox, matching its Firefox
UA — so **no h2 rule fires on it**. That is the expected and important result: Camoufox runs genuine
Firefox networking (Necko), so the HTTP/2 layer cannot distinguish it from a real Firefox any more than
the TLS layer can. Camoufox is beaten by capability/environment tells and by coordination, never by
network-stack incoherence — and the live h2 capture confirms that boundary rather than assuming it.

### JA4 must be matched on the cipher prefix, not the full string

The same capture exposed why the TLS-engine hint was blank for Camoufox: the JA4 hint table keyed on the
*full* JA4, but Camoufox randomises its TLS extension *set* per launch, so JA4_c (the extension hash)
changes every run while JA4_a (version/cipher/extension counts) and JA4_b (the cipher hash) stay fixed.
JA4 deliberately sorts ciphers and extensions before hashing — robust against Chrome's extension-*order*
shuffling — but sorting cannot survive a changing extension *set*, which is exactly the lever Camoufox
pulls. The fix is to fall back to the `JA4_a+JA4_b` prefix: it pins the TLS stack (cipher list) without
depending on the volatile extension set. Seeded with the live Camoufox prefix
(`t13d1717h2_5b57614c22b0`), the edge now classifies the Firefox TLS family, so `net.tls_vs_ua_browser`
and `net.h2_vs_tls_browser` can cross-check the TLS engine for Firefox-based tools — they stay quiet on
Camoufox itself (coherent Firefox) but would fire on a tool wearing a non-Firefox UA over a Firefox TLS
stack. A cipher prefix pins the engine but not the OS, so the OS hint is emitted only when present —
otherwise a blank OS would have falsely fed `net.tls_os_vs_tcp_os`.

## Locale coherence across the HTTP/JS boundary

The same value is often visible at two layers, set from one source of truth — and a spoof that rewrites
one layer but not the other splits them apart. The browser's UI locale is exactly such a value: a real
browser derives both the HTTP `Accept-Language` request header *and* the JS `navigator.languages` from one
setting, so they always agree on the primary language. A bot that overrides `navigator.languages` in JS
(to look German, say) but runs its HTTP client with a default `Accept-Language: en-US` contradicts itself
across the network/browser boundary. The edge emits the primary language subtag of `Accept-Language`, the
collector emits the subtag of `navigator.languages[0]`, and `net.accept_lang_vs_navigator` (cross-layer,
so the incoherence weight applies) fires when they differ. The comparison is on the language *subtag*
only (`en`, not `en-US`) so an `en-US` vs `en-GB` region nuance never false-positives — it flags a wholly
different language, the shape an actual locale spoof takes. This is the cheapest possible instance of the
core thesis: no new capture machinery, just two layers reporting the same fact and a check that they match.

The **OS** is the same kind of value, and it splits even more cleanly. Chrome sets the
`Sec-CH-UA-Platform` client-hint header from the *real* operating system at the network layer, when the
request is sent. The common UA spoof — CDP `setUserAgent` (or a JS override) without the matching
`userAgentMetadata` — rewrites `navigator.platform`/the UA string but **not** the header Chrome already
emitted, so a bot running real Chrome on Linux while presenting as Windows sends `Sec-CH-UA-Platform:
"Linux"` alongside a Windows `navigator` platform. `net.ch_platform_header_vs_ua` (cross-layer, 0.6) fires
on that split. The edge normalises the header to the collector's exact OS vocabulary
(Windows/macOS/Linux/Android) and emits nothing for values outside it (Chrome OS, iOS) — where the
collector could not classify `ua_platform` either — so the two only ever compare like with like. Firefox
and Safari never send the header, so the rule is naturally scoped to the Chromium UA-spoof case it targets
and cannot false-positive on a non-Chromium browser.

The **browser brand** completes the set. Chromium sends `Sec-CH-UA` (the brand list, e.g.
`"Chromium";v="126", "Google Chrome";v="126"`) built from its *real* brand, and a JS-level UA override
does not touch it — confirmed live: a Chromium driven with a Firefox `User-Agent` still sends
`Sec-CH-UA: chrome` while `navigator.userAgent` reads Firefox. `net.ch_ua_vs_ua_browser` (cross-layer,
0.6) maps the brand list to the collector's browser vocabulary (Edge if "Microsoft Edge" is present, else
any Chromium brand → chrome; Firefox/Safari send no header so it never fires on them) and compares it to
the JS `ua_browser`. The pay-off is visible on the refreshed `spoof-ua` recording: a single Firefox-UA-on-
Chromium spoof now trips **three independent cross-layer rules at once** — `net.tls_vs_ua_browser` (the
JA4 TLS engine), `net.h2_vs_ua_browser` (the HTTP/2 stack), and `net.ch_ua_vs_ua_browser` (the client-hint
brand) — each reading the true engine from a different layer the UA string cannot reach. That triple is
the thesis in miniature: the spoof only had to rewrite one string, and three lower layers disagree with it.

A fourth client-hint coherence closes the *version* dimension. The UA string and the `Sec-CH-UA` brand
list both carry the Chromium major version, and a real browser keeps them identical. Scrapers, though,
routinely assemble a header set by hand — a `User-Agent` copied from one Chrome release and a `Sec-CH-UA`
copied from another — and the two versions drift apart. `net.ch_ua_version_vs_ua` compares the UA-string
`Chrome/<major>` against the real Chromium-family brand version in `Sec-CH-UA` (skipping the GREASE
`"Not.A/Brand"` entry, comparing major-only so Chrome's reduced UA never false-positives) and fires on a
mismatch. Live-checked with a crafted request — `Chrome/126` UA, `Sec-CH-UA` v=124 — it fires; against a
real browser, which never disagrees with itself here, it stays silent. With browser, OS, locale, and now
version, every low-entropy client hint a request carries is cross-checked against the layer it should
agree with.

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
