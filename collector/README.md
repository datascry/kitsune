# collector/ — in-browser signal collection (TypeScript)

Kitsune's **client-side** signal collector. It runs as the page's own script, reads fingerprint and
behavioral tells from the live browser, and POSTs contract-valid `Signal` envelopes to the detector.
Each envelope carries the `ks_sid` correlation id the edge set as a cookie, so browser telemetry
joins the network-layer signals into one session for the coherence engine to score.

There are **two builds** from the same source:

- **collector** (`src/index.ts`) — the production page script. Arms listeners, snapshots a
  `BrowserEnv`, and ships a focused set of `browser.*` + `behavioral.*` signals to the detector's
  `/ingest`.
- **livepage** (`src/livepage/`) — a standalone, CreepJS / sannysoft-style self-test page. It runs
  the **full** probe suite client-side, evaluates the detector's coherence rules in the browser, and
  renders a per-layer verdict locally. No POST; useful for white-box probing of an anti-detect tool.

> See [`docs/architecture.md`](../docs/architecture.md) for where the collector sits in the lab.

## Design

Browser globals are abstracted behind a `BrowserEnv` interface (`types.ts`), so the production
collection logic is **pure and testable without a real browser** (logic coverage gated ≥95%, ≈100%
today). Only `index.ts` touches live globals — thin glue, excluded from the coverage gate (tier-2 IO,
verified via build + e2e). The livepage's `probes.ts`/`render.ts`/`main.ts` are likewise live-DOM
glue and excluded from the unit gate.

| Module           | Role                                                                                  |
| ---------------- | ------------------------------------------------------------------------------------- |
| `signal.ts`      | Build contract-valid `Signal` envelopes (stamps `schema_version`, `source=collector`).|
| `detect.ts`      | UA → browser/platform labels; normalise Client-Hints platform (feeds UA↔CH coherence).|
| `behavioral.ts`  | Quantify pointer + keystroke motion into the behavioral signals the detector scores.   |
| `cdp.ts`         | Arm the CDP `Runtime.enable` probe (prototype-chain Proxy `ownKeys` trap).             |
| `session.ts`     | Read the `ks_sid` correlation cookie.                                                  |
| `collect.ts`     | Assemble a session's signals from a `BrowserEnv` snapshot (pure).                      |
| `transport.ts`   | POST signals to the detector's `/ingest` (injected `fetch`).                           |
| `index.ts`       | Production entrypoint: wire live DOM/navigator probes, collect, send.                  |
| `livepage/`      | The self-test page: full probe suite + client-side rule engine + verdict render.       |

## Signals the production collector emits (`collect.ts`)

- `browser.webdriver`, `browser.webdriver_spoofed` (own-property `defineProperty` patch tell),
  `browser.ua_browser`, `browser.ua_platform`, `browser.ch_platform` (Client-Hints), `browser.ua_is_headless`.
- `browser.canvas_lie` — `HTMLCanvasElement.prototype.toDataURL` no longer stringifies to `[native code]`.
- `browser.cdp_runtime_enabled` — the `cdp.ts` Proxy trap fired (live replacement for the dead V8
  `Error.stack` trick; see `docs/catalog.md` §4).
- `browser.fp_hash` — FNV-1a/32 over a canvas-text render folded with the WebGL renderer/vendor.
  Varies per GPU/driver/OS/font-stack, so two real machines differ; an identical hash across distinct
  IPs is one cloned anti-detect profile (the coordination scorer's profile-reuse tell).
- `behavioral.mouse_entropy`, `behavioral.pointer_event_count`, `behavioral.keystroke_entropy`, and —
  once there are ≥3 pointer samples — `behavioral.mouse_straightness` and `behavioral.mouse_velocity_cv`.

Boolean tells and shape features are emitted **only when present/derivable**, so absence resolves as
genuinely MISSING in the detector (not a false `false`).

### Behavioral features (`behavioral.ts`)

- **mouse_entropy** — normalised Shannon entropy of quantised movement directions (8 bins). Straight
  or absent motion → ~0 (the human-entropy floor); varied human motion → high.
- **mouse_straightness** — straight-line / total path length, in [0,1]. A scripted straight drag → ~1.
- **mouse_velocity_cv** — coefficient of variation (std/mean) of segment speeds. Constant-speed
  automation → ~0; variable human motion → high.
- **keystroke_entropy** — normalised entropy of inter-keystroke intervals. Constant cadence → ~0.
- **pointer_event_count** — raw sample count.

## The livepage self-test (`livepage/`)

`main.ts` arms listeners, fetches the rule registry (`rules.json`, emitted by the harness), waits a
few seconds for the visitor to move/type, snapshots the full signal map via `armCollector().collect()`,
then evaluates only the **client-evaluable** rules (`predicates.ts` + `engine.ts`) and renders a
verdict (`scoring.ts` mirrors the Python detector's noisy-or + incoherence amplification, with
matching thresholds). The behavioral layer is only scored once there is enough genuine interaction
(≥15 pointer samples / ≥4 keystrokes), so an idle human is not scored as a bot.

`probes.ts` is the large, comprehensive port of the detector's demo-page probes. Major probe
**families**:

- **Automation / CDP tells** — `webdriver` + getter tampering, `cdp_runtime_enabled`, `cdc_*`
  artifacts, Playwright/Puppeteer/Selenium/PhantomJS automation globals and DOM attributes,
  `electron_process` (Node `process` leak), missing/empty `chrome` runtime object.
- **Native-function / `toString` integrity** — `function_tostring_tampered`, `native_invariant_violated`
  (a claimed-native built-in that is a constructor or owns a `prototype`), `webgl_getparameter_tampered`,
  webdriver/Notification getter tampering.
- **Navigator / UA-CH coherence** — UA-string vs `navigator.platform`/`oscpu`/`vendor`/`productSub`
  vs Client-Hints; UA-CH high-entropy checks (`ch_he_headless`, `ch_he_version_vs_ua`); engine
  cross-checks via error-message text, `Math.pow` last-bit, V8 `captureStackTrace`, and a
  `Promise.withResolvers` stale-template-vs-UA tell; spoofed/empty nav properties.
- **GPU / rendering** — WebGL renderer/vendor (software-rasterizer, ANGLE-wrapper, OS-hint, artifact
  strings), WebGPU adapter info, and **WebGPU↔WebGL** vendor/hardware mismatch.
- **Canvas / audio / fonts / media** — canvas pixel-noise (farbling) detection, OfflineAudioContext
  fingerprint + audio readback-noise, font OS-hints and Linux/mac signature-font leaks, `measureText`
  main-vs-OffscreenCanvas divergence, codec/OS coherence, WebRTC, media-device enumeration, speech voices.
- **Realm coherence** — the headline family. Compares values across the **main thread vs a Web Worker
  (and an iframe)**: `worker_divergence` (UA/cores/platform), `languages_worker_divergence`,
  `webgl_worker_divergence` (Worker `OffscreenCanvas` renderer), `canvas_worker_divergence` (main vs
  Worker canvas pixel-hash), `timezone_worker_divergence`, and `iframe_divergence`. A JS main-realm
  spoof (GPU/canvas/geo/locale) cannot reach Worker scope, so the Worker reports the real value.
  Backstopped by `worker_constructor_tampered` — a `Worker`/`OffscreenCanvas` constructor that no
  longer reads as native, closing the escalation path of wrapping the constructors to inject the spoof.
- **Environment / layout invariants** — `domrect_invariant_violated` (non-deterministic
  `getBoundingClientRect`), screen/colour-depth/DPR anomalies, `pointer_touch_incoherent`,
  `permissions_anomaly`, `csp_bypassed`, anti-`rfp` (resist-fingerprinting) heuristics.

> The Worker probes duplicate their draw/hash code as **strings** (e.g. `CW_DRAW` and the inline
> `mainCanvasHashCW` ops, which MUST stay byte-identical). This is deliberate: `build:livepage` runs
> `tsup --minify`, which mangles function names, so passing `fn.toString()` into a Worker is unsafe.

## Develop

Node may not be installed in every environment — use Docker (`node:22-alpine`) if so.

```sh
pnpm install
pnpm test          # vitest run --coverage (gate ≥95%, currently ≈100% on covered logic)
pnpm run typecheck # tsc --noEmit: strict + noUncheckedIndexedAccess + exactOptionalPropertyTypes
pnpm run lint      # eslint .
pnpm run format:check
pnpm run build           # tsup → dist/ (ESM + d.ts) — the production collector
pnpm run build:livepage  # tsup --minify → site-build/ — the standalone self-test page
```

> Contracts are the only coupling: the collector emits the `Signal` envelope defined in
> `contracts/signal.schema.json` (mirrored in `types.ts`) and never imports another component.
