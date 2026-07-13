# collector/ — in-browser signal collection (TypeScript)

Kitsune's **client-side** signal collector. It runs as the page's own script, reads fingerprint and
behavioral tells from the live browser, and POSTs contract-valid `Signal` envelopes to the detector.
Each envelope carries the `ks_sid` correlation id the edge set as a cookie, so browser telemetry
joins the network-layer signals into one session for the coherence engine to score.

This package is the **production page script** (`src/index.ts`) — it arms listeners, snapshots a
`BrowserEnv`, and ships a focused set of `browser.*` + `behavioral.*` signals to the detector's
`/ingest`. The **full** in-browser probe suite + coherence verdict lives in the detector's own inline
collector (`detector/…/demo.py`), the public inspector at kitsune.id — see
[`docs/architecture.md`](../docs/architecture.md) §3 for the two-collector split.

> A former standalone self-test page (`src/livepage/`) was removed — it duplicated `demo.py`'s job and
> was never deployed. `demo.py` is the one canonical inspector.

## Design

Browser globals are abstracted behind a `BrowserEnv` interface (`types.ts`), so the production
collection logic is **pure and testable without a real browser** (logic coverage gated ≥95%, ≈100%
today). Only `index.ts` touches live globals — thin glue, excluded from the coverage gate (tier-2 IO,
verified via build + e2e).

| Module          | Role                                                                                   |
| --------------- | -------------------------------------------------------------------------------------- |
| `signal.ts`     | Build contract-valid `Signal` envelopes (stamps `schema_version`, `source=collector`). |
| `detect.ts`     | UA → browser/platform labels; normalise Client-Hints platform (feeds UA↔CH coherence). |
| `behavioral.ts` | Quantify pointer + keystroke motion into the behavioral signals the detector scores.   |
| `cdp.ts`        | Arm the CDP `Runtime.enable` probe (prototype-chain Proxy `ownKeys` trap).             |
| `session.ts`    | Read the `ks_sid` correlation cookie.                                                  |
| `collect.ts`    | Assemble a session's signals from a `BrowserEnv` snapshot (pure).                      |
| `transport.ts`  | POST signals to the detector's `/ingest` (injected `fetch`).                           |
| `index.ts`      | Production entrypoint: wire live DOM/navigator probes, collect, send.                  |

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

> The full in-browser probe suite (automation/CDP tells, native-`toString` integrity, UA-CH coherence,
> GPU/WebGPU, canvas/audio/fonts, **realm coherence** across main-vs-Worker/iframe, environment
> invariants) lives in the detector's inline collector (`detector/…/demo.py`) — the authoritative
> full suite. This package ships only the focused production subset.

## Develop

Node may not be installed in every environment — use Docker (`node:22-alpine`) if so.

```sh
pnpm install
pnpm test          # vitest run --coverage (gate ≥95%, currently ≈100% on covered logic)
pnpm run typecheck # tsc --noEmit: strict + noUncheckedIndexedAccess + exactOptionalPropertyTypes
pnpm run lint      # eslint .
pnpm run format:check
pnpm run build     # tsup → dist/ (ESM + d.ts) — the production collector
```

> Contracts are the only coupling: the collector emits the `Signal` envelope defined in
> `contracts/signal.schema.json` (mirrored in `types.ts`) and never imports another component.
