# Detection landscape — Kitsune vs. the live-detection field

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
| **S1** | **CSS⇄JS channel coherence (new no-JS axis).** CSS `@media` beacon layer (pointer/hover/color-gamut/resolution/`forced-colors`/`prefers-color-scheme`) cross-checked against the JS equivalents (`maxTouchPoints`, `devicePixelRatio`, color scheme). Convict on clear CSS-vs-JS contradiction; corroborate `no_js_execution` with beacon-absence. Confirm a current evader (e.g. mobile-emulation) creates the mismatch before shipping a convicting rule. | M | coherence | ◐ in progress — EVADES confirmed |
| **S2** | **Multi-oracle GPU/OS cross-check.** Predict GPU family independently from canvas-hash + WebGL renderer + (new) emoji/text-metric render; convict on cross-oracle disagreement. Extends WebGL↔WebGPU match. Ground vs a renderer-spoof evader. | M–L | coherence | ☐ not started |
| **S3** | **Realm-coherence breadth.** Extend the Worker-realm checks to SharedWorker / ServiceWorker / AudioWorklet. Verify a stealth tool leaks an un-patched realm before convicting. | M | coherence | ☐ not started |
| **S4** | **Native-lie battery expansion.** Add `Reflect.ownKeys === [length,name]` exact-match, descriptor-keys, `class extends` tamper tests. Calibrate against real-browser captures first (engine/version variance) before convicting. | S–M | artifact | ☐ not started |
| **S5** | **Emoji / DOMRect render coherence.** Emoji + `getClientRects()` sub-pixel metrics as an added GPU/farbling oracle, cross-realm. Deterministic on a real engine. | S–M | coherence | ☐ not started |
| **S6** | **`forced-colors` / `color-gamut` as OS corroborators.** Windows High-Contrast + Apple-P3 as corroborating-only OS signals vs UA. FP-safe by construction (never convicts alone). | S | environment | ☐ not started |

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
