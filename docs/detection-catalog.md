# detection-catalog — gaps from the blue-team enumeration fleet

A subagent fleet enumerated bot-detection techniques across CreepJS, FingerprintJS/BotD, stealth-plugin
inverses, DataDome/Kasada/Cloudflare/Akamai/HUMAN, fingerprint surfaces, live production-JS reverse
engineering, and network/transport research, then gap-analyzed every technique against Kitsune's ruleset.

**Result: ~56 techniques already covered, 24 genuine gaps.** Coherence + automation are
near-saturated; the gaps cluster in deeper fingerprint-content checks, automation invariants, and a few
network refinements. Prioritize **FP-safe** gaps (the calibration showed adding FP-prone environment
tells is what flags real browsers) — i.e. low-fp coherence/automation/artifact gaps over medium-fp ones.

> **Per-session saturation, measured (v0.73.1, 2026-06-19).** Scoring all 40 **real captured** evader
> sessions (`corpus/sessions/`, the live-stack second source — not browserforge) through the current
> ruleset: **every evader scores `bot`**, including the top-tier stealth tools (`max-stealth`,
> `full-stealth`, `patchright`, `selenium-driverless`, `camoufox-hardened`, `zendriver`, `nodriver`,
> `rebrowser`, `undetected`). There is **no escaping evader** to build a new per-session detection against.
> The remaining catalog gaps below are either un-groundable in this sandbox (need a real GPU / real device /
> headful — `canvas_hash_engine_vs_ua`, `emoji_os_vs_ua`, `webgpu_limits`), confirmed-defeated
> (`h_order_vs_ua`), or FP-prone environment tells that only corroborate. Net: per-session convicting
> coverage is **saturated**; the live frontiers (real-residential-proxy harness, Tier-3 real-device matrix,
> real-hardware-headful) are blocked by sandbox limits. Iterations now harden the structural frontiers
> (prevalence prior, coordination gate) and the calibration's trustworthiness instead of grinding marginal
> tells. The detection matrix (`matrix.md`) is regenerated from these captures against the current ruleset;
> the latest refresh added the 2 newest rules with **no catch-count regression** on any existing rule.

## Prioritized gaps

| suggested rule | priority | fp-risk | effort | technique |
|---|---|---|---|---|
| `br.canvas_hash_engine_vs_ua` | high | medium | medium | Canvas hash vs engine baseline — Hash toDataURL vs Blink/Gecko/WebKit/SwiftShader baselines. |
| `net.h_order_vs_ua` | high | medium | medium | JA4H header order & casing — On-wire header order/casing is per-stack; browser UA over non-browser order is a tell. |
| `bh.interact_without_focus` | high | medium | easy | document.hasFocus coherence — Interaction (pointer/keystroke/submit) while document.hasFocus() false is incoherent. |
| `br.readback_noise` | high | low | easy | getImageData/audio readback-noise — getImageData and getChannelData-vs-copyFromChannel must round-trip identical bytes; diverg |
| `br.native_invariant_violated` | high | low | medium | Native prototype-lie suite — Illegal-invocation throw, non-constructability, ownKeys=length,name, prototype-in-fn false |
| `br.electron_process` | high | low | easy | Electron process leak — Electron exposes a Node process object in the renderer; a real browser never does. |
| `br.measuretext_os_vs_ua` | medium | medium | medium | measureText OS signature — measureText metrics encode OS renderer; main vs OffscreenCanvas divergence; Camoufox spoof |
| `br.emoji_os_vs_ua` | medium | medium | medium | Emoji glyph vs OS — Emoji raster hash + tofu-vs-glyph maps to OS/version; Windows UA with Noto emoji is incohe |
| `br.isolated_world` | medium | medium | hard | Isolated-world execution tell — Main-world sentinel unreachable from isolated-world automation (selenium-driverless/patchr |
| `br.stack_tool_marker` | medium | low | easy | Error.stack tool-marker leak — Error().stack leaks pptr/puppeteer/playwright/_evaluation_script__ markers. |
| `br.domrect_invariant` | medium | low | medium | DOMRect transform geometry — getClientRects on transformed/zero-size elements; per-engine sub-pixel + invariant checks. |
| `bh.honeypot_interaction` | ✅ DONE | low | medium | Honeypot bait interaction — Hidden bait element/field; automation that touches/fills it trips. Very low FP. SHIPPED as `br.honeypot_interaction` (automation) v0.74.11. |
| `net.ja4t_vs_ua` | medium | low | medium | JA4T active TCP fingerprint — TCP window/options-order/MSS/wscale; JA4T-vs-TLS-engine incoherence is a second TCP anchor |
| `br.timer_resolution_vm` | low | high | medium | performance.now VM timing — VM/headless timer resolution/jitter + micro-benchmark distinguish virtualized hosts. |
| `net.tls_raw_value_anomaly` | low | medium | medium | JA4_r raw value anomaly — Raw cipher/ext hex values vs claimed-browser profile; catches a value the hashed JA4 hides |
| `br.webgpu_limits_incoherent` | low | medium | medium | WebGPU limits/features bucket — adapter.limits/features bucket must match the GPU class; stock limits on a high-end vendor |
| `br.hw_memory_implausible` | low | medium | easy | hwc/deviceMemory plausibility — Default/round/implausible hwc+deviceMemory pairings signal VMs. |
| `br.storage_quota_anomaly` | low | medium | easy | Storage quota disk leak — storage.estimate quota ~60% of disk; containers report small/round; identical across sessi |
| `br.gamut_vs_gpu` | low | medium | easy | color-gamut/HDR vs GPU — P3/HDR display claim while software-rendering (SwiftShader) is suspicious. |
| `br.battery_anomaly` | low | medium | easy | Battery API stub/presence — Chrome clamps getBattery; varying values, or presence/absence wrong for the engine, is inc |
| `br.sensor_vs_formfactor` | low | medium | medium | Sensor presence vs form factor — DeviceMotion/Sensor presence must match mobile-ness; mobile UA with no motion, or static s |
| `br.broken_image_dims` | low | medium | easy | Broken-image dimensions — Headless renders a broken img at 0x0; real Chrome ~16x16. |
| `rep.ja4_traffic_shape` | low | medium | hard | JA4 aggregate traffic-shape — Per-JA4 browser_ratio/h2h3_ratio/quantile vs genuine same-JA4 baseline flags spoofed fps. |
| `br.antidetect_tool_hash` | low | low | medium | Anti-detect extension hash — Hash patched prototype-method source to name CanvasBlocker/JShelter/puppeteer-extra. |

## Build order (precision-first)

The low-FP, high-priority gaps are the safe wins (they add detection without raising the 23% legitimate-
browser flag rate the calibration measured):

1. **`br.readback_noise`** — `getImageData`/audio `copyFromChannel` must round-trip identical bytes; a
   noise/farbling shim diverges. Deeper than `canvas_noise` (which only probes a solid fill). Easy, low FP.
2. **`br.electron_process`** — a renderer exposing a Node `process` object is Electron, never a real browser.
3. **`br.native_invariant_violated`** — illegal-invocation throw / non-constructability / ownKeys checks:
   a Proxy-based spoof passes `tostring_tampered` (native-code string) yet fails these. Low FP.
4. **`br.stack_tool_marker`** — `Error().stack` leaks `puppeteer`/`playwright`/`_evaluation_script__` markers.
5. **`net.h_order_vs_ua`** — JA4H regular-header order/casing vs claimed browser (in progress).

Medium-FP gaps (`canvas_hash_engine_vs_ua`, `measuretext_os`, `emoji_os`, `interact_without_focus`) are
valuable but need careful calibration against the real-browser corpus before shipping active.

## Shipped from this catalog

- ✅ `br.honeypot_interaction (ACTIVE — the classic honeypot, the catalog's bh.honeypot_interaction gap. The collector injects an off-screen, aria-hidden, tabIndex=-1 bait link + input a human literally cannot reach; a click on the bait or a value in the bait input is a programmatic DOM-enumeration interaction → automation. FP-safe: fires ONLY on a definitive hit, never on absence; grounded against clean headful Chromium AND Firefox (no fire). Fires in-context via the stealth HONEYPOT=1 form-spammer evader.)`
- ✅ `net.h2_header_order_vs_ua (ACTIVE v0.74.13 — promoted from experimental after two independent non-Chrome h2 stacks corroborated: httpx/h2 (http2-naive) and curl/nghttp2 (curl-http2), both faking a Chrome UA with a non-Chrome regular-header order. Real Chrome + all 40+ Chrome impersonators emit the Sec-CH-UA-first order → never fire. Catches the naive h2 scraper that fakes Chrome without replicating its on-wire order.)`
- ✅ `br.readback_noise`
- ✅ `br.electron_process`
- ✅ `br.native_invariant_violated`
- ✅ `br.domrect_invariant`
- ✅ `br.measuretext_offscreen_vs`
- ✅ `br.fingerprint_improbable (prevalence model — the structural frontier)`
- ✅ `br.webgl_worker_vs_main (experimental — GPU analog of worker_divergence; fires live on full-stealth + native-spoof; pending Tier-3 real-GPU FP validation)`
- ✅ `br.canvas_worker_vs_main (experimental — canvas analog; a Worker OffscreenCanvas hash vs main; fires live on canvas-spoof; pending Tier-3 real-GPU FP validation)`
- ✅ `br.timezone_worker_vs_main (ACTIVE — geo-spoof analog; main vs Worker timezone; FP-safe (process-level, legit CDP override propagates to workers); fires live on tz-spoof)`
- ✅ `br.languages_worker_vs_main (experimental — language half of the geo-spoof pair; main vs Worker navigator.languages; fires live on lang-spoof; experimental NOT active because a legit CDP locale override does not propagate to workers, so it needs Tier-3 legit-divergence-rate validation)`
- ✅ `br.worker_constructor_tampered (ACTIVE — the escalation guard for the whole realm-coherence family; window.Worker/OffscreenCanvas must be native; fires live on worker-wrap, which defeats worker_divergence by injecting the spoof into worker scope but cannot keep the Worker constructor native)`
- ✅ `br.timezone_offset_vs_intl (ACTIVE — internal timezone coherence; getTimezoneOffset must match the Intl IANA zone's actual offset; self-contained, no worker/IP-geo; FP-safe (real + legit CDP override both coherent); fires live on naive-tz-spoof and the wrong-season tz-spoof)`
- ✅ `br.canvas_geometry_noise (ACTIVE — canvas GEOMETRY farbling, the JShelter white-box tell from evasion-catalog; isPointInPath is an exact GPU-independent hit-test, deterministic in every real engine; 120 trials on a deep-interior + far-exterior point catch a ~5%-flip farbler at ~99.8%; FP-safe (missing API never fires, only a definitive verdict counts) — zero FP across browserforge calibration; distinct from canvas_noise/Brave readback farbling)`
- ✅ `br.apple_ua_nonwebkit (ACTIVE — iOS/Safari engine lock; Apple mandates WebKit for Safari AND every iOS browser (Chrome=CriOS, Firefox=FxiOS, Brave, DuckDuckGo, Onion all wrap system WebKit), so a UA claiming Apple WebKit that exposes a Blink-only structural API — window.chrome, navigator.userAgentData, or V8 Error.captureStackTrace — is a Chromium host faking an iOS/Safari UA. STRUCTURAL positive-API tell (survives error-message/float spoofing that error_engine/math_engine rely on). Catches the common mobile-Safari-UA spoof on headless Chromium. **v0.74.9: narrowed to TWO arms** — the Error.captureStackTrace arm was dropped after a live headful WebKit capture (corpus/calibration/headful/) proved JSC ships captureStackTrace since Safari 16.4, i.e. the arm convicted real Safari 16.4+/iOS users; window.chrome / userAgentData remain genuinely Blink-only so the spoof catch is preserved — see docs/calibration.md "Tier-2")`

_Skipped: `br.stack_tool_marker` — the collector runs as the page's own inline script, so its Error().stack is clean regardless of automation (can't fire here)._

## Live-page browser discrimination (white-box identification)

The live page predicts the **real** browser from feature detection (`collector/src/livepage/predict.ts`),
independent of the spoofable UA, and names it: **Brave** (`navigator.brave`), **Chrome / Edge / Opera /
Samsung Internet** (UA-CH brands + `window.chrome`), **Firefox** (Gecko: `-moz-appearance` / `buildID` /
`mozInnerScreenX`), **Safari** (WebKit), and the **Tor / Mullvad Browser** family (Gecko + the
resistFingerprinting conjunction: UTC timezone + a 200×100-letterboxed window + ≤2 cores — the same
signature the detector's `br.rfp_browser` ships and calibrates, so a vanilla Firefox is not mislabeled).

**Mobile + privacy browsers** are named with the same honesty about what features *can* prove:
- **iOS** — Apple forbids non-WebKit engines, so Safari, Chrome (CriOS), Firefox (FxiOS), Brave, DuckDuckGo,
  and Onion Browser all run the *same* system WebKit. The engine cannot separate them, so the page reports
  `iOS browser (WebKit)` and says so — and the detector's convicting `br.apple_ua_nonwebkit` fires on any UA
  that claims iOS/Safari while exposing a Blink-only API (a Chromium host faking an iOS UA).
- **Android** — `Brave`/`Opera`/`Edge`/`Chrome` carry an `(Android)` tag; a Blink engine with no vendor tell
  is named `Chromium (Android)` (Vivaldi/Yandex/UC/DuckDuckGo-Android suppress their brand — not guessed);
  Gecko is `Firefox / GeckoView (Android)` (Firefox/Focus/Fennec share the engine), and the RFP-Gecko variant
  is `Tor Browser / Mull (Android)`.

**Honest limit:** Tor Browser and Mullvad Browser are *intentionally identical* at the JS layer (they share
one anonymity set), so they are not JS-separable — only the **network layer** (a Tor exit-IP via
`rep.*`/IP reputation) tells them apart. The prediction surfaces this in its evidence rather than guessing.

**Per-browser FP suppression (the point of the prediction).** `notApplicable(ruleId, prediction)` excludes
a tell that is *expected* for the identified browser so it cannot convict a real user:
- platform-coherence (`navplatform/webgl/oscpu_vs_ua`) on **mobile** (Android's `Linux` platform is genuine);
- Chromium-only capability tells (`no_chrome_object`, `no_connection`, …) on **non-blink** engines;
- **Brave's by-design farbling** (`canvas_noise`, `audio_noise`) when the browser is positively **Brave**
  (the definitive `navigator.brave` global) — Brave's default Shields perturb the canvas/audio readback, so a
  real Brave user (~70M of them) would otherwise noisy-or two *artifact* (convicting) tells to `bot`. A
  Chrome-claiming farbler with no `navigator.brave` (an anti-detect tool) still convicts.

> **Detector-side parity (done, v0.73.3).** The same Brave farbling FP existed server-side; the detector now
> has its own per-browser N/A (`detector.applicability`, the analog of the live page's `predict.notApplicable`).
> The collector emits `browser.is_brave` (from `navigator.brave`); `Detector.score` drops the Brave-expected
> farbling artifacts (`canvas_noise`, `audio_noise`) before scoring when the session is Brave, so a real Brave
> user is not convicted. A Chrome-claiming farbler with no `navigator.brave` still convicts, and a Brave-faking
> bot is still caught by its automation tells, so it cannot help a bot escape. Calibration is unchanged
> (browserforge never emits `is_brave`, so the filter is a no-op there).
