# evaders/stealth — Playwright multi-mode evader (real)

Status: **live** ✅ — drives a real Chromium (or a patchright / rebrowser-playwright drop-in) through
the edge and is scored by the detector. Runs in the official Playwright Docker image; a single
`run.mjs` selects a mode by env var. This is the fleet's workbench: each mode demonstrates one
specific anti-detect failure mode, and together they exercise the detector's single-layer,
cross-layer, **realm-coherence**, and behavioral rules.

## What it does

Launches Chromium, navigates the edge (which fingerprints the TLS handshake and serves the collector
page), drives the pointer/keyboard, lets the in-page collector POST browser + behavioral signals, then
reads the verdict back by `ks_sid`. Output is a single `__KS__`-prefixed JSON line so the orchestrator
can extract it past any engine noise.

## Modes

Selected by env var (`MODE=1`, or `SPOOF_UA=<ua>`). `engine` is `patchright` for the patchright-based
modes, `rebrowser-playwright` for `REBROWSER`, else stock `playwright`.

### Baseline

| Env | Mode | Demonstrates |
|---|---|---|
| *(none)* | naive | plain automation — leaks `webdriver`, HeadlessChrome UA, and fixed-interval typing |
| `STEALTH=1` | stealth | patches `webdriver`, presents a real Chrome UA — defeats the single-layer FP checks |
| `SPOOF_UA=<ua>` | spoof-ua | patched webdriver + a *lying* UA (e.g. Firefox) over real Chrome TLS → `net.tls_vs_ua_browser` cross-layer; a Windows UA over the Linux edge → `net.tcp_os_vs_ua` |
| `FULL=1` | full-stealth | the full JS-injection battery (webdriver on the prototype, fake plugins, fake WebGL GPU string, Linux-Chrome UA) |
| `FLOOR_SPOOF=1` | floor-spoof | patchright + Linux-Chrome UA, then fakes the environment floor nothing else spoofs (TTS voices, `enumerateDevices`, `pdfViewerEnabled`, `Notification.permission`) — tests whether those tells are a real wall or just catch the absent case |
| `PATCHRIGHT=1` | patchright | the patchright anti-detect drop-in (best CDP-leak stealth) |
| `REBROWSER=1` | rebrowser | rebrowser-patches — another `Runtime.enable`-leak fix |
| `MAX_STEALTH=1` | max-stealth | the kitchen sink: patchright + coherent Linux-Chrome UA + human-like motion |

### Realm-coherence spoofs (the key red-team contribution)

Each spoofs navigator/canvas/geo in the **main** realm the lazy way but forgets a sibling scope
(Web Worker, same-origin iframe), so the detector's divergence probe catches the realm the patch never
reached. These exercise the worker/iframe realm-coherence rules directly.

| Env | Mode | Skipped realm | Caught by |
|---|---|---|---|
| `WORKER_SPOOF=1` | worker-spoof | Worker global scope (UA / `hardwareConcurrency`) | `br.worker_divergence` |
| `IFRAME_SPOOF=1` | iframe-spoof | dynamically-created same-origin iframe (top-frame-only guard) | `br.iframe_divergence` |
| `NATIVE_SPOOF=1` | native-spoof | prototype invariant — fakes `getParameter` `toString` but the plain fn is constructable | `br.native_invariant_violated` (where `tostring_tampered` is silent) |
| `CANVAS_SPOOF=1` | canvas-spoof | Worker `OffscreenCanvas` (main-realm farble only) | `br.canvas_worker_vs_main` |
| `TZ_SPOOF=1` | tz-spoof | Worker timezone (residential-proxy geo-spoof on main thread only) | `br.timezone_worker_vs_main` |
| `LANG_SPOOF=1` | lang-spoof | Worker `navigator.languages` (geo-spoof on main thread only) | `br.languages_worker_vs_main` |

### Runtime artifact

| Env | Mode | Caught by |
|---|---|---|
| `ELECTRON_LEAK=1` | electron-leak | leaks a Node `process` into the renderer (`process.versions.electron` + `process.type="renderer"`) the way an Electron app with nodeIntegration on does → `br.electron_process` (automation). A real web browser has no Node process; the headful captures confirm absence. Gives that active rule its first live positive. |
| `STALE_ENGINE=1` | stale-engine | claims a Chrome 125 UA but removes `Promise.withResolvers` (shipped Chrome 119) → `br.engine_feature_vs_ua` (coherence). Faithfully simulates a hardcoded-modern-UA-on-an-older-build (the JS analog of a lagging TLS/PQ template). A real Chrome ≥121 ships the feature; the headful Chromium capture does not trip it. Gives that active rule its first live positive. |

### Escalation

| Env | Mode | Demonstrates |
|---|---|---|
| `WORKER_WRAP=1` | worker-wrap | wraps `window.Worker` so worker code inherits the same spoof — **defeats** `worker_divergence`, but the non-native `Worker` constructor trips `br.worker_constructor_tampered`. The realm-coherence escalation: hiding from the divergence guard forces a structural lie the escalation guard catches. |

### Behavioral

| Env | Mode | Demonstrates |
|---|---|---|
| `HUMAN_MOUSE=1` | human-mouse | bézier-curved, ease-in-out, micro-jittered motion — the **negative control** that must NOT trip the biomech floor |
| `LINEAR_BOT=1` | linear-bot | a single straight-line drag at constant velocity → `bh.path_too_straight` + `bh.uniform_velocity`; with human-mouse, proves the biomech rules discriminate scripted from human motion |

## Headline result

| mode | network | browser | incoherence | label | caught by |
|---|---|---|---|---|---|
| naive | 0.00 | **0.985** | 0.00 | bot | `br.webdriver_present`, `br.headless_ua` |
| stealth | 0.00 | 0.00 | 0.00 | human | — (defeats the single-layer FP checks) |
| **spoof-ua** | **0.70** | **0.70** | **0.70** | **bot** | **`net.tls_vs_ua_browser` (cross-layer)** |

`stealth` passes every single-layer check. `spoof-ua` *also* passes every single-layer check
(webdriver patched, valid Firefox UA, valid Chrome TLS) — yet it's caught because its **TLS says Chrome
while its UA says Firefox**. That cross-layer incoherence is the entire thesis, live.

## Run

```sh
docker compose up -d --build detector edge
docker build -t kitsune-stealth ./evaders/stealth
docker run --rm --network kitsune_default \
  -e KITSUNE_EDGE=https://edge:8443/ -e KITSUNE_DETECTOR=http://detector:8080 \
  -e WORKER_SPOOF=1 kitsune-stealth          # swap the env flag for any mode above
```

`scripts/live_scoreboard.sh` runs the full set of modes and renders each as a scoreboard row.
