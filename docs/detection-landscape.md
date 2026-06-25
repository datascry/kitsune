# Detection landscape — Kitsune vs. the live-detection field

> **Browser-layer gap analysis (S1–S6 backlog)** — for the broad field survey incl. commercial anti-bot
> see [`landscape.md`](landscape.md).

A capability-gap analysis of Kitsune's demo/collector against the major live browser-fingerprinting and
bot-detection pages (CreepJS, Sannysoft, Intoli, FingerprintJS BotD, pixelscan, iphey, browserscan,
bot.incolumitas.com), plus how each handles false positives and what pure-CSS (no-JS) detection adds.
Source-grounded from each tool's own source/docs; see citations inline. Drives the **S1–S6 backlog** below.

## Two axes

The field lives on one axis each; Kitsune spans two.

- **In-browser JS axis** — fingerprint surfaces + lie-detection + behaviour, client-side. (CreepJS, Sannysoft,
  Intoli, BotD, pixelscan, iphey, browserscan, incolumitas.)
- **Wire axis** — TLS JA3/JA4, HTTP/2, QUIC/H3, TCP/IP, below the JS layer.

Kitsune fuses **both into one correlated, server-side session and flags incoherence across them**, plus two
things no public page does: **cross-session fleet/coordination clustering** and **within-session temporal
invariance** (JA4/h2/UA/IP/fp/trace rotation). The serious pages (pixelscan, iphey, incolumitas,
Fingerprint Pro) have independently converged on Kitsune's *"incoherence, not rarity"* thesis.

## Where Kitsune leads

| Capability | Best public page |
|---|---|
| TLS JA3/JA4 ⇄ H2 ⇄ QUIC ⇄ TCP **fused with JS** in one session | incolumitas (partial: JA3+TCP, unfused) |
| Cross-session **fleet/coordination** clustering | none |
| **Within-session** invariant-rotation | none |
| **Coalesced-pointer-event** structural tell + power-law biomechanics (grounded vs Balabit/SapiMouse) | incolumitas (behavioural, no coalesced) |
| **Server-side authority** (rules unspoofable from client) | CreepJS/BotD are client-side (evadable) |
| Category-gated **conviction + calibration FP regression** (browserforge+Intoli+fpgen) | iphey/pixelscan (consistency only; no FP suite) |

## Gaps vs. the field (browser-layer probe mechanisms present elsewhere, absent/shallow here)

1. **Multi-oracle GPU/OS prediction cross-check** — CreepJS predicts GPU/OS independently from canvas, WebGL,
   audio, emoji, math and convicts on cross-oracle disagreement. Kitsune only does WebGL↔WebGPU family match. → **S2**
2. **Native-lie test battery depth** — CreepJS runs `Reflect.ownKeys === [length,name]` exact-match,
   descriptor-keys, `class extends`, multiple proxy-trap error-shape tests. Kitsune's base is narrower. → **S4**
3. **Realm-coherence breadth** — Kitsune covers Workers but not **SharedWorker / ServiceWorker / Worklets**. → **S3**
4. **Emoji / DOMRect render coherence** — CreepJS uses emoji + `getClientRects()` sub-pixel metrics as a
   GPU/farbling oracle. Kitsune has canvas/audio/webgl but not emoji/DOMRect. → **S5**
5. **No CSS / no-JS channel at all** — every Kitsune browser signal needs JS. → **S1, S6**
6. Minor: `forced-colors`/`color-gamut` as OS corroborators; speech-voice/WebGPU depth; storage-API coherence.

**Deliberately NOT gaps (discipline):** math last-ULP entropy (Kitsune *retired* it — build/CPU-dependent →
FPs on real Chromium; do NOT re-add). Convicting on canvas/audio **farbling or rarity** — CreepJS and pixelscan
both confirm Kitsune's choice to treat farbling as engine-native and not convict on uniqueness.

## False-positive handling across the field

Eight distinct FP-avoidance strategies; Kitsune already implements the principled ones (3–7) and its calibration
gate is stronger FP discipline than any public page (none run a real-traffic FP regression).

| # | Strategy | Who | Kitsune |
|---|---|---|---|
| 1 | Discard the spoofed source, don't convict | CreepJS (drops `lied` fields) | ✗ — convicts on tamper (correct for a bot detector) |
| 2 | Separate "spoof/incoherence" from "bot" label | CreepJS, pixelscan, iphey | ◐ category split; live page could surface it |
| 3 | Coherence over uniqueness | pixelscan, iphey, CreepJS | ✅ core thesis |
| 4 | Rarity not penalised / crowd-blending | pixelscan, CreepJS | ✅ prevalence corroborating-only |
| 5 | Convict only on definitive signatures | BotD (`BotKind` else `undefined`) | ✅ automation/artifact categories |
| 6 | Require multi-signal corroboration | incolumitas (30+), DataDome | ✅ conviction gate + 2nd-source gates |
| 7 | Graded confidence + human-favouring threshold | incolumitas (0.5, time-gated), iphey (3-tier) | ✅ noisy-or + suspicious band + ≥65% gate |
| 8 | Raw per-check, no aggregate | Sannysoft, Intoli | ✗ by design (Kitsune scores a verdict) |

Borrowable: CreepJS's clean *"what you claimed vs. what you actually are"* presentation (#1/#2) — a live-page
UX improvement, not a scoring change.

## Pure-CSS / no-JS detection

CSS can't send data but triggers conditional fetches (`background:url()` / `@font-face` / `content:url()` behind
`@media`/`@supports`/selectors, per-value URLs with a per-visitor token); the server learns the value from which
URL was hit. Works with JS disabled, in Tor, in email.

- **Detectable:** resolution, `device-pixel-ratio`, `color`/`color-gamut` (p3→Apple), `dynamic-range`,
  `forced-colors` (Windows High-Contrast→OS tell), `prefers-color-scheme`/`-contrast`, `hover`/`any-hover`,
  `pointer`/`any-pointer` (coarse=touch), `@font-face local()` font/OS inference, `@media (scripting: none)`.
- **Automation:** strongest CSS tell is **absence of the second-wave fetch** — curl/requests/Scrapy grab HTML
  and never load conditional CSS resources. CSS **cannot** distinguish well-built headless (renders normally).
- **Research/PoCs:** Cascading Spy Sheets (CISPA, NDSS 2025, `github.com/cispa/cascading-spy-sheets`);
  CrookedStyleSheets (`github.com/jbtronics/CrookedStyleSheets`); Fingerprint.com "Disabling JS Won't Save You";
  css-tricks.com/css-based-fingerprinting.
- **Why it matters here:** the CSS `@media` channel and the JS channel report the *same* facts independently — a
  spoof that patches `navigator.maxTouchPoints` in JS but not `@media (any-pointer)` is a cross-channel
  contradiction no anti-detect tool currently covers, and beacon-absence corroborates `net.no_js_execution`.

---

## S1–S6 backlog (the loop drains this in priority order)

Each rung follows the standing grounding discipline: **confirm the evasion EVADES the current detector first →
build the probe/collector → build the grounded blue rule → verify it CONVICTS the evader AND passes the FP gates
(`task calibrate` / `calibrate-intoli`) + per-component CI (detector/harness via `uv`, edge/collector via Docker,
`task catalog` after any registry change) → commit CI-green as datascry (no Co-Authored-By) → push to the PR**.
Never ship an ungrounded convicting rule. If a rung proves FP-unsafe or not-groundable in-sandbox, mark it
`resolved — not built` with the rationale (like `font_os_vs_ua`/G6) and move on.

| ID | Improvement | Size | Category | Status |
|---|---|---|---|---|
| **S1** | **CSS⇄JS channel coherence (new no-JS axis).** CSS `@media` beacon layer cross-checked against the JS equivalents. The first pairing tried — `@media (any-pointer: coarse)` vs `navigator.maxTouchPoints` — is **FP-unsafe** (headful-grounded, below). | M | coherence | ✗ resolved — not built (pointer/touch FP-unsafe; see note) |
| **S2** | **Multi-oracle GPU/OS cross-check.** Predict GPU family independently from canvas-hash + WebGL renderer + (new) emoji/text-metric render; convict on cross-oracle disagreement. Extends WebGL↔WebGPU match. Ground vs a renderer-spoof evader. | M–L | coherence | ✗ resolved — core covered; new oracle external-data-bound (see note) |
| **S3** | **Realm-coherence breadth.** Extend the Worker-realm checks to SharedWorker / ServiceWorker / AudioWorklet. Verify a stealth tool leaks an un-patched realm before convicting. | M | coherence | ✗ resolved — named realms redundant/FP-prone; real residual speculative (see note) |
| **S4** | **Native-lie battery expansion.** Add `Reflect.ownKeys === [length,name]` exact-match, descriptor-keys, `class extends` tamper tests. Calibrate against real-browser captures first (engine/version variance) before convicting. | S–M | artifact | ✗ resolved — not built (grounded: adds no coverage; see note) |
| **S5** | **Emoji / DOMRect render coherence.** Emoji + `getClientRects()` sub-pixel metrics as an added GPU/farbling oracle, cross-realm. Deterministic on a real engine. | S–M | coherence | ✗ resolved — coherence covered; prediction oracle Tier-3-bound (see note) |
| **S6** | **`forced-colors` / `color-gamut` as OS corroborators.** Windows High-Contrast + Apple-P3 as corroborating-only OS signals vs UA. FP-safe by construction (never convicts alone). | S | environment | ✗ resolved — not built (FP-prone OS mapping + redundant; see note) |

### Iteration log

- **2026-06-22 · S1 step (a) — EVADES confirmed.** The current `br.pointer_touch_incoherent` rule
  (demo.py ~L975) reads BOTH sides via JS: `matchMedia("(any-pointer: coarse)")` vs
  `navigator.maxTouchPoints`. An anti-detect tool that hooks `window.matchMedia` (or sets both
  consistently) makes `cssTouch === jsTouch` → the rule is JS-evadable. A pure-CSS `@media` *beacon*
  (a `background:url()` the rendering engine fetches per matched media value) is NOT JS-hookable, so the
  beacon-reported pointer/DPR/color-scheme vs the JS-reported equivalents catches the coherent-JS spoof
  that beats the current rule. The edge (`edge/internal/proxy/handler.go`) serves via `http.ServeMux`
  (`/healthz`, `/fingerprint`, `/ingest`, reverse proxy) — the beacon endpoint (`GET /b/<sid>/<key>/<value>`)
  + a served stylesheet are the next chunk (step b). Grounding rationale established; no rule shipped yet.
- **2026-06-22 · S1 — RESOLVED, not built (pointer/touch CSS⇄JS FP-unsafe).** Built the beacon collector
  (cookie-correlated `/b/` receiver + `@font-face` `@media (any-pointer: coarse)` beacon + `js_touch`) and the
  detector-side derivation, then **grounded it headful** (`harness/tools/css_beacon_ground.mjs`: real Chromium
  via Playwright/xvfb, route-intercepting the engine's beacon fetch). Result killed the convicting rule:

  | case | CSS `any-pointer:coarse` | JS `maxTouchPoints` | agree |
  |---|---|---|---|
  | desktop-no-touch | false | 0 | ✓ |
  | real-touch (emulated) | **false** | **1** | ✗ |
  | js-spoof-maxtouch | false | 5 | ✗ |

  A **legitimate touch context** produces `any-pointer:coarse ≠ maxTouchPoints>0` — CSS `any-pointer` semantics
  ("any coarse pointer present") genuinely diverge from the touch-digitizer count under emulation / hybrid
  (2-in-1) / xvfb. The convicting rule would FALSE-POSITIVE on real touch/hybrid devices, indistinguishable
  from the spoof (same direction). Per the standing discipline this is the **G6 / `font_os_vs_ua` pattern**:
  the probe was built, grounded, and the rule REVERTED rather than shipped FP-prone. The beacon collector +
  derivation were reverted too (no dead code); the grounding tool stays as the evidence + a reusable harness.
  S1's no-JS-beacon *idea* survives for an FP-SAFER pairing (devicePixelRatio via `@media (resolution)`, or
  `prefers-color-scheme`, where the CSS media and the JS value are exactly equivalent on real browsers) — left
  as a future candidate, not pursued now. Net: one FP averted, the channel design + grounding harness banked.
- **2026-06-22 · S2 — RESOLVED, core already covered + new oracle external-data-bound.** S2's central idea —
  cross-checking GPU oracles and convicting on disagreement — is **already shipped and convicting**:
  `br.webgpu_vendor_vs_webgl` (active, coherence, w0.75) fires when the WebGL-renderer GPU family and the
  WebGPU-adapter GPU family disagree (a spoofed WebGL string on real hardware showing through WebGPU); the
  worker-realm oracles (`br.webgl_worker_vs_main`, `br.canvas_worker_vs_main`) cover main-vs-worker GPU/canvas.
  Probed live: a renderer-spoof with a disagreeing WebGPU adapter -> `br.webgpu_vendor_vs_webgl` fires -> bot;
  the SAME renderer-spoof on a **no-WebGPU target** (older/blacklisted GPU, headless) has no convicting GPU
  tell -> evades. Closing that residual needs the genuinely-NEW oracle S2 proposed: predict GPU family from the
  **canvas-hash / emoji render** (CreepJS's encrypted-samples approach) and convict on disagreement with the
  WebGL string. That requires a **Tier-3 real-GPU reference corpus** (render -> GPU-family map across real
  devices) — the exact wall already documented for `br.fingerprint_improbable` (gpu single-source pending
  Tier-3) and `br.webgl_worker_vs_main` (grounded only on software rendering). Building the canvas->GPU oracle
  in-sandbox would be ungrounded (no real-GPU data to learn the mapping or prove FP-safety), so it is routed to
  the external/grounding-harness queue, not built. No new rule; the GPU-oracle cross-check S2 wanted exists.
- **2026-06-22 · S3 — RESOLVED, realm coherence already comprehensive; named realms redundant/FP-prone.** The
  Worker-realm family is mature and robust: `br.worker_divergence` (worker navigator != main), the FUNDAMENTAL
  `br.worker_source_rewritten` (self.location.href != passed blob URL — documented robust to the ENTIRE
  Worker-disguise ladder: WORKER_WRAP / WORKER_PROXY / WORKER_PROXY_FIX, all grounded-live), plus
  `br.worker_constructor_tampered` and the per-attribute `*_worker_vs_main` (languages/timezone/webgl/canvas).
  Probed: both realm-evasion classes already convict — a main-only navigator spoof → `worker_divergence` (bot);
  a worker-scope injection → `worker_source_rewritten` (bot). Assessing the named extensions:
  **SharedWorker** is a second worker realm catching the SAME divergence/injection kinds already caught
  (defense-in-depth duplication, not new coverage); no current evader beats the Worker realm but leaks
  SharedWorker (confirm-EVADES fails), and it is unavailable in major real contexts (Chrome on Android, some
  privacy modes) → FP-handling overhead for redundant coverage. **ServiceWorker** is heavyweight (HTTPS +
  persistent async registration + cache side-effects), restricted in many contexts, and its scope cannot read
  navigator like a Worker → FP-prone + limited. **AudioWorklet**'s `AudioWorkletGlobalScope` has no `navigator`
  → cannot do navigator-coherence. The one REAL residual (the existing rules' own documented next rung) is the
  `WorkerLocation.prototype.href` override (a tool echoing the original URL to beat `worker_source_rewritten`,
  leaving a non-native `WorkerLocation.href` in worker scope) — but no current evader performs it, so per
  confirm-EVADES-first it stays the documented next rung, not built. No new rule; realm coherence is covered.
- **2026-06-22 · S4 — RESOLVED, not built (grounded: exact-own-keys adds no coverage).** Headful-grounded the
  native-lie expansion across real Chromium + Firefox + WebKit (`harness/tools/native_lie_ground.mjs`). FP
  baseline: every present native method (`permissions.query`, `toDataURL`, `getParameter`, `Function.prototype.bind`)
  has `Reflect.ownKeys` exactly `["length","name"]` on ALL THREE engines — so an exact-own-keys check is
  FP-safe. But the evader run kills its value: a **Proxy-over-native** method (the real threat that defeats the
  current toString/own-prototype/constructibility checks — `claimsNative=true, ownProto=false, constructible=false`)
  also forwards `Reflect.ownKeys → ["length","name"]`, so exact-own-keys does NOT catch it; and a **sloppy
  wrapper** with extra own keys has `claimsNative=false`, already caught by the existing toString check. So the
  proposed exact-own-keys / descriptor-keys tests add ZERO catches (the evasions are already caught or forward
  right past them). Closing the residual (transparent Proxy over a native non-constructor method) would need
  fragile engine-version-specific proxy-trap error-shape tests (S1-class FP risk) AND is redundant: the spoof's
  OUTPUT is already caught by output-coherence rules (`permissions_anomaly` etc.) — Kitsune catches the
  injection consequence, not the wrapper structure (the existing `worker_constructor_tampered` /
  `worker_source_rewritten` design). No new rule; grounding tool kept as evidence + reusable harness.
- **2026-06-22 · S5 — RESOLVED, coherence covered + prediction oracle Tier-3-bound (mirrors S2).** The render
  coherence S5 proposes is already shipped and firing (probed): `br.domrect_invariant` (artifact — DOMRect
  determinism + `getClientRects()` consistency, the geometry oracle), `br.measuretext_offscreen_vs` (artifact —
  text-metric main-vs-OffscreenCanvas oracle), and `br.canvas_worker_vs_main` (coherence — cross-realm canvas
  render). The genuinely-NEW part — emoji/DOMRect render → PREDICT GPU/OS family (CreepJS's encrypted-samples
  oracle) and convict on cross-oracle disagreement — needs a **Tier-3 real-device reference corpus** to learn
  the render→family map and prove FP-safety, the exact wall `br.canvas_worker_vs_main` already documents
  ("stays corroborating until validated against a Tier-3 real-GPU device") and the same one that resolved S2.
  Cross-realm *emoji* coherence specifically would be only marginal extra draw-ops on the already-experimental
  canvas-realm rule, not new capability. No new rule; routed external (Tier-3), same queue as S2.
- **2026-06-22 · S6 — RESOLVED, not built (FP-prone OS mapping + redundant).** `forced-colors`/`color-gamut`
  as OS corroborators fail the FP-safety bar (a corroborator that lifts the legit-browser flag rate is the
  prevalence-rule trap): **color-gamut: p3 is NOT Apple-exclusive** — it is standard on modern non-Apple
  displays (Dell/Samsung/Pixel laptops+phones, most external monitors), so "p3 ⟹ Apple" false-positives broadly;
  **forced-colors: active is rare** (accessibility-gated; most users off → almost never contributes) AND **not
  strictly Windows** (Linux GTK high-contrast; the spec permits UA triggers), and it carries no human-vs-bot
  discrimination. Both would be weaker, FP-prone additions to an already-strong, grounded OS-corroborator set
  (`webgl_os_vs_ua`, `navplatform_vs_ua`, `oscpu_vs_ua`, `font_os_vs_ua`, `voice_os_vs_ua`, `font_linux_leak`,
  `font_mac_internal`, `codec_os_incoherent`) — the same FP-prone-OS-mapping lesson as `font_os_vs_ua` / G6.
  No new rule.

### Backlog outcome — S1–S6 DRAINED (2026-06-22)

All six AI-proposed improvements are resolved; **no new convicting rule shipped, no FP introduced** — the
disciplined outcome. The throughline: Kitsune's coherence/native-invariant engine already covers what the
in-browser detection field (CreepJS et al.) does, and the genuinely-new capabilities are either FP-unsafe in
real browsers or external-data-bound (Tier-3 real-device corpus). Per-rung:

| rung | outcome | why |
|---|---|---|
| S1 | resolved (FP-unsafe) | CSS `any-pointer` ≠ `maxTouchPoints` in legit touch/hybrid contexts (headful-grounded) — rule reverted |
| S2 | resolved (covered + external) | WebGL↔WebGPU oracle already convicts (`webgpu_vendor_vs_webgl`); canvas→GPU oracle needs Tier-3 |
| S3 | resolved (covered + redundant) | Worker-realm coherence already robust; SharedWorker/ServiceWorker/AudioWorklet redundant/FP-prone |
| S4 | resolved (grounded no-coverage) | exact-own-keys forwards through a Proxy-over-native (3-engine headful); spoof output already caught |
| S5 | resolved (covered + external) | DOMRect/measureText/canvas-realm oracles already shipped; emoji→GPU prediction needs Tier-3 |
| S6 | resolved (FP-prone + redundant) | `color-gamut`/`forced-colors` are not clean OS tells; redundant with 8 existing OS corroborators |

Banked: two reusable headful grounding harnesses (`harness/tools/css_beacon_ground.mjs`,
`native_lie_ground.mjs`) and the cross-engine FP baselines. External queue (Tier-3 real-device / real-GPU
corpus) gains the canvas/emoji→GPU-family oracle (S2/S5) — routed to `docs/grounding.md`, not built in-sandbox.
This confirms the in-browser detection frontier is saturated, consistent with the per-session-saturation finding.
