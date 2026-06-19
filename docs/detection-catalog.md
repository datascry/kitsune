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
| `net.h_order_vs_ua` | ✅ DONE | medium | medium | JA4H header order & casing — On-wire header order/casing is per-stack; browser UA over non-browser order is a tell. SHIPPED as `net.h2_header_order_vs_ua` (active v0.74.13, two-source corroborated). |
| `bh.interact_without_focus` | ❌ DEAD | medium | easy | document.hasFocus coherence — Interaction (pointer/keystroke/submit) while document.hasFocus() false is incoherent. DEAD: grounded out — document.hasFocus() is `true` in headless Chromium (identical to headful), so there is no signal and the rule cannot fire in our context. |
| `br.readback_noise` | ✅ DONE | low | easy | getImageData/audio readback-noise — getImageData and getChannelData-vs-copyFromChannel must round-trip identical bytes; diverg SHIPPED (active; live-validated via audio-readback-spoof). |
| `br.native_invariant_violated` | ✅ DONE | low | medium | Native prototype-lie suite — Illegal-invocation throw, non-constructability, ownKeys=length,name, prototype-in-fn false SHIPPED (active; native-spoof evader). |
| `br.electron_process` | ✅ DONE | low | easy | Electron process leak — Electron exposes a Node process object in the renderer; a real browser never does. SHIPPED (active; no Electron evader in the fleet so unexercised, but live-producible). |
| `br.measuretext_os_vs_ua` | medium | medium | medium | measureText OS signature — measureText metrics encode OS renderer; main vs OffscreenCanvas divergence; Camoufox spoof |
| `br.emoji_os_vs_ua` | medium | medium | medium | Emoji glyph vs OS — Emoji raster hash + tofu-vs-glyph maps to OS/version; Windows UA with Noto emoji is incohe |
| `br.isolated_world` | medium | medium | hard | Isolated-world execution tell — Main-world sentinel unreachable from isolated-world automation (selenium-driverless/patchr |
| `br.stack_tool_marker` | ❌ DEAD | low | easy | Error.stack tool-marker leak — Error().stack leaks pptr/puppeteer/playwright/_evaluation_script__ markers. DEAD: the collector runs as the page's own inline script, so its Error().stack is clean regardless of automation — cannot fire in our context. |
| `br.domrect_invariant` | ✅ DONE | low | medium | DOMRect transform geometry — getClientRects on transformed/zero-size elements; per-engine sub-pixel + invariant checks. SHIPPED (active). |
| `bh.honeypot_interaction` | ✅ DONE | low | medium | Honeypot bait interaction — Hidden bait element/field; automation that touches/fills it trips. Very low FP. SHIPPED as `br.honeypot_interaction` (automation) v0.74.11. |
| `net.ja4t_vs_ua` | ❌ REDUNDANT / ungroundable | low | medium | JA4T active TCP fingerprint — TCP window/options-order/MSS/wscale. RESOLVED (2026-06-19, not worth building): JA4T encodes the **OS TCP stack** (a browser uses the OS's stack), and the edge already parses the SYN (`ParseSYN`) and derives OS coherence via `ClassifyTCPOS` → `net.tcp_os_vs_ua`. So JA4T-vs-UA is the SAME SYN-derived OS-coherence signal we already ship, just a different encoding — redundant. AND ungroundable: FoxIO's `ja4plus-mapping.csv` ja4t column is EMPTY for Chrome/Firefox/Safari (JA4T is OS/path-specific, not a stable browser baseline), so there is no second source to ground per-browser JA4T against. |
| `br.timer_resolution_vm` | low | high | medium | performance.now VM timing — VM/headless timer resolution/jitter + micro-benchmark distinguish virtualized hosts. |
| `net.tls_raw_value_anomaly` | low | medium | medium | JA4_r raw value anomaly — Raw cipher/ext hex values vs claimed-browser profile; catches a value the hashed JA4 hides |
| `br.webgpu_limits_incoherent` | low | medium | medium | WebGPU limits/features bucket — adapter.limits/features bucket must match the GPU class; stock limits on a high-end vendor |
| `br.hw_memory_implausible` | low | medium | easy | hwc/deviceMemory plausibility — Default/round/implausible hwc+deviceMemory pairings signal VMs. |
| `br.storage_quota_anomaly` | low | medium | easy | Storage quota disk leak — storage.estimate quota ~60% of disk; containers report small/round; identical across sessi |
| `br.gamut_vs_gpu` | low | medium | easy | color-gamut/HDR vs GPU — P3/HDR display claim while software-rendering (SwiftShader) is suspicious. |
| `br.battery_anomaly` | low | medium | easy | Battery API stub/presence — Chrome clamps getBattery; varying values, or presence/absence wrong for the engine, is inc |
| `br.sensor_vs_formfactor` | low | medium | medium | Sensor presence vs form factor — DeviceMotion/Sensor presence must match mobile-ness; mobile UA with no motion, or static s |
| `br.broken_image_dims` | ❌ DEAD | medium | easy | Broken-image dimensions — Headless renders a broken img at 0x0; real Chrome ~16x16. DEAD: grounded out — a broken <img> is 0x0 in headless AND headful Chromium, so there is no signal to mismatch. |
| `rep.ja4_traffic_shape` | low | medium | hard | JA4 aggregate traffic-shape — Per-JA4 browser_ratio/h2h3_ratio/quantile vs genuine same-JA4 baseline flags spoofed fps. |
| `br.antidetect_tool_hash` | low | low | medium | Anti-detect extension hash — Hash patched prototype-method source to name CanvasBlocker/JShelter/puppeteer-extra. |
| `br.chrome_runtime_authenticity` | ⛔ Tier-3-BLOCKED | high | medium | chrome.runtime AUTHENTICITY (not presence) — NEW gap surfaced by the headful-patchright red-team work. `br.chrome_runtime_missing` (demo.py:742) is a PRESENCE-only check (`window.chrome && !window.chrome.runtime`), trivially cleared by faking `window.chrome.runtime = {}` (the FLOOR_SPOOF mode already does this → it does NOT trip the rule). It is the **only deterministic convicting browser-layer catch** for headful patchright (the rest is timing-dependent `quic_grease` + corroborating env/behavioural), so a patchright-class tool that also fakes chrome.runtime would defeat the deterministic browser layer. Fix = verify chrome.runtime is AUTHENTIC (native `connect`/`sendMessage`, real shape). **BLOCKED:** cannot ground authentic chrome.runtime in-sandbox — Playwright Chromium lacks chrome.runtime entirely, and there is no real non-Playwright Chrome here; shipping the check without that ground truth risks FP on real Chrome (constraint #6). Needs a Tier-3 real-Chrome capture. See docs/evasion-catalog.md. |

## Build order (precision-first) — COMPLETE

The original precision-first build order is now fully resolved: `br.readback_noise`, `br.electron_process`,
`br.native_invariant_violated`, and `net.h_order_vs_ua` (as `net.h2_header_order_vs_ua`) all **shipped active**;
`br.stack_tool_marker` is **DEAD** in our context (the collector is the page's own inline script, so its
`Error().stack` is clean regardless of automation). The low-FP/high-priority queue is exhausted.

**Per-session convicting detection is SATURATED.** The remaining table rows are either shipped (✅), grounded-
out dead-ends (❌: `interact_without_focus` — `document.hasFocus()` is `true` in headless too;
`broken_image_dims` — 0×0 in headless and headful alike), medium-FP environment tells that need a real-device
corpus to calibrate (`canvas_hash_engine_vs_ua`, `measuretext_os`, `emoji_os`, `gamut_vs_gpu`, `hw_memory`,
`storage_quota`, `battery_anomaly`, `sensor_vs_formfactor`), or blocked on inputs the sandbox cannot produce
(`ja4t_vs_ua`/`tls_raw_value` need an edge-side JA4T/JA4_r build; `webgpu_limits` needs a real GPU;
`ja4_traffic_shape`/`rep.*` IP-reputation need a real residential-proxy source; the prevalence model's
gpu/colour/cores factors need a Tier-3 real-device matrix to corroborate browserforge).

One **new convicting gap** was surfaced (2026-06-19) by the headful-patchright red-team work and is the
clearest per-session frontier, but it too is Tier-3-blocked: `br.chrome_runtime_authenticity`. The current
`br.chrome_runtime_missing` is presence-only and is the *sole deterministic* browser-layer catch for headful
patchright; faking `window.chrome.runtime` clears it (FLOOR_SPOOF already does). The fix — an authenticity
check — cannot be FP-safely grounded in-sandbox (no real non-Playwright Chrome to observe a genuine
`chrome.runtime`), so it is deferred to a Tier-3 real-Chrome capture rather than shipped ungrounded.

The productive frontier has shifted to **red-team-driven validation** (build the evader that exercises a
known-good rule, ground the real-browser negative) — which cleared the "Evaded" rule queue and surfaced the
engine-identity family — and to **periodic live re-validation + scoreboard/matrix refresh** (see
docs/calibration.md). New marginal per-session tells are deliberately NOT pursued at saturation.

### Frontier activation runbook — the turnkey infra is built; supply the data, run the command

The structural-frontier consumption infrastructure is built and tested, so each frontier is now
**data-only-blocked** (no further code needed — supply the external data the sandbox can't generate and
run the command). The one entry point:

| frontier | what to supply | command (already built + tested) |
|---|---|---|
| **Prevalence — independent prior** (fixes browserforge same-source blindness) | real-traffic SESSION captures (a hosted-demo opt-in yields these; shape = `corpus/sessions/*.json`) | `cd harness && uv run python -m kitsune_harness.browserforge_corpus --build-prior-from-sessions <dir>` (or `--build-prior-from-dir` for raw fingerprint dicts). Detector then loads the new prior automatically. See docs/prevalence-model.md. |
| **Live proxy / coordination harness** (activates `rep.*`, `net.webrtc_ip_vs_observed`, proxy-topology signals) | real residential/datacenter proxy endpoints | `IMAGE=… N=… PROXIES="socks5://p1,socks5://p2,…" OUT=corpus/fleet-proxy harness/tools/fleet_capture.sh` then grade with `kitsune_harness.coordination`. Refresh CIDR seeds first: `python -m kitsune_detector.ip_reputation_refresh`. See docs/coordination-proxy.md. |
| **`br.chrome_runtime_authenticity`** (the one per-session gap) | a real (non-Playwright) **Chrome** capture, to ground authentic `window.chrome.runtime` | NOT turnkey yet — needs a real-Chrome session through the collector first, THEN add a `chrome.runtime`-shape probe + the FP-safe authenticity rule (grounded against that capture). The capture path (collector + `/session`) exists; the probe+rule are a small follow-up once real-Chrome data lands. |

So two of the three are pure data drops; the third needs a real-Chrome capture before its (small) probe+rule
can be written FP-safely. Nothing here is buildable further in-sandbox without that external data.

### Saturation is PROVEN, not asserted — the emitted-vs-consumed audit (2026-06-19)

Saturation was re-confirmed systematically rather than by inspection: diff every signal the collector
**emits** against every signal a rule **consumes**.

```sh
# emitted kinds (collector): the S("<layer>","<kind>",…) calls in detector/src/kitsune_detector/demo.py
grep -rhoE 'S\("(network|browser|behavioral|reputation)",[[:space:]]*"[a-z_0-9]+"' \
  detector/src/kitsune_detector/demo.py | grep -oE '"[a-z_0-9]+"[[:space:]]*$' | tr -d '" ' | sort -u
# consumed kinds (rules): the reads: lists in contracts/rules/registry.yaml
grep -oE '(network|browser|behavioral|reputation)\.[a-z_0-9]+' contracts/rules/registry.yaml \
  | sed -E 's/^[a-z]+\.//' | sort -u
```

Of 112 emitted kinds, **all but 12 feed a rule directly**, and every one of those 12 is accounted for —
none is an unbuilt **convicting** (coherence/automation/artifact) gap:

- **Raw-value inputs to the structural models, by design** (not direct rule predicates): `fp_hash` +
  `trace_hash` (coordination collision signals), `color_depth` + `screen_resolution` + `webgl_renderer`
  (prevalence factors / `webgl_os_hint` derivation), `webgl_vendor` + `webgpu_vendor`.
- **WebGPU-absence environment tells** (`webgpu_absent`/`webgpu_fallback`/`webgpu_no_adapter`): environment
  tier — corroborating only, and the convicting WebGPU coherence (`webgpu_*_mismatch`) is already ruled.
- **Dead collection — two behavioural metrics** (`pause_ratio`, `submovement_count`): collected but read by
  no rule. They are *behavioural*, hence corroborating-only/FP-prone, so wiring them would be a marginal
  non-convicting tell — deliberately NOT built at saturation. Flagged here as a latent corroborating option
  (or remove from the collector) for a future biomech pass, not a detection gap.

So there is provably **no unconsumed signal that could become a convicting per-session rule** — the gate is
saturated against the current collection surface. New convicting coverage now requires either a new
collector signal (new attack surface) or the structural frontiers (prevalence second prior; live proxy
coordination), both of which are external-data-blocked as noted above.

## Shipped from this catalog

- ✅ `br.safari_ua_no_webkit_api (ACTIVE v0.74.18 — completes the engine-identity family. window.GestureEvent is a WebKit-ONLY global (every desktop + iOS Safari since Safari 5; Blink and Gecko have none). A Safari UA without it is a non-WebKit faker — the negative-surface complement to apple_ua_nonwebkit (which keys on Blink APIs PRESENT), robust to a spoof that DELETES window.chrome/userAgentData to beat that rule. GROUNDED on the real-browser second source (live Playwright WebKit GestureEvent="function" vs Chromium/Firefox undefined); real headful WebKit does NOT fire, the ios-ua-spoof evader (Chromium under an iPhone Safari UA) does. FP-safe: every real Safari has GestureEvent. The three engine-identity tells now cover all three: chromium↔engine_stack, gecko↔firefox_ua_nongecko (buildID), webkit↔this (GestureEvent) + apple_ua_nonwebkit (Blink-present).)`
- ✅ `br.firefox_ua_nongecko (ACTIVE v0.74.17 — the Gecko analog of apple_ua_nonwebkit. navigator.buildID is a Gecko-ONLY surface (every real Firefox/Tor/Mullvad/fork exposes it, release builds frozen to "20181001000000"; Blink and WebKit have none). A Firefox UA without buildID is a non-Gecko engine faking Firefox. STRUCTURAL positive-surface tell, complementary to engine_stack_vs_ua: a spoof that deletes Error.captureStackTrace to beat engine_stack still cannot synthesise a real Gecko buildID. GROUNDED on the real-browser second source (live Playwright Firefox buildID="20181001000000" vs Chromium undefined) + the real-Gecko firefox-os-spoof evader does NOT fire (it IS Gecko); the spoof-ua evader (Chromium under a Firefox UA) does. FP-safe: every real Gecko has buildID → never fires on real Firefox.)`
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
