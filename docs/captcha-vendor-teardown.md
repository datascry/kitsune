# Captcha vendor teardown — clean-room functional findings

A behavioural characterization of mainstream captcha widgets, produced with Kitsune's owned instrumentation
(`harness/tools/captcha_probe.js` + `captcha_probe_diff.mjs`). The probe wraps the fingerprint/behavioural/network
JS APIs, records every access in first-touch order across **all frames**, and diffs the target against a baseline
(Kitsune's own collector at `kitsune.id`). It observes *behaviour* — which APIs are read, which events are
subscribed, which endpoints are hit and with what payload **shape** — never any vendor's code.

**Method + scope.** Each vendor's *public developer demo* was probed once, on the operator's own machine (not the
lab — the lab is allow-list-scoped to owned infra). This is understanding-only: characterize the mechanism to
reproduce it vendor-neutrally, never to solve or proxy a live service. Deltas are **relative to Kitsune's
collector** — an empty `signals_target_only` means "Kitsune already reads that surface," not "the vendor reads
nothing."

## Results

| Vendor | Frames observed | Signal delta vs collector | Behavioural (extra listeners) | Endpoints captured |
|---|---|---|---|---|
| **reCAPTCHA v2** | `google.com` ×3 + `about:blank` ×2 | `battery.getBattery`, `storage.estimate` | huge: pointer/mouse/key/focus/contextmenu/keypress/storage | — (exchange via frame nav) |
| **hCaptcha** | `accounts.hcaptcha.com` + `newassets.hcaptcha.com` | `audio.createAnalyser`, `webgl.getShaderPrecisionFormat`, `screen.pixelDepth`, `storage.estimate` | heavy: mouse/key/wheel/`copy`/`resize` + `unhandledrejection` | `GET *.w.hcaptcha.com/logo.png`; **`POST api.hcaptcha.com/checksiteconfig?…&sitekey=…&sc=1&swa=1&spst=1`** |
| **Cloudflare Turnstile** | `demo.turnstile.workers.dev` + `challenges.cloudflare.com` | none | `message`, `error`, `animationend` | — |
| **Arkose / FunCaptcha** | `demo.arkoselabs.com` only | none | `mousedown/up`, `touchcancel`, `keyup`, `popstate` | — (widget did not load) |
| **GeeTest v4** | `gt4.geetest.com` only | none | `message`, `resize`, `animationstart`, mouse-enter/leave | — (widget not triggered) |

## Per-vendor reading

**hCaptcha — the richest, and the clearest protocol.** Two frames (`accounts` shell + `newassets` challenge).
It reads a real fingerprint delta beyond the collector — an **audio** analyser node, a **WebGL** shader-precision
probe, screen **pixelDepth**, and a **storage** quota estimate — on top of heavy mouse/keyboard/wheel behaviour.
Crucially the probe captured its **token/config protocol**: a `POST` to `checksiteconfig` carrying the sitekey and
config flags (`sc`/`swa`/`spst`), plus challenge-asset `GET`s to per-widget `*.w.hcaptcha.com` hosts. This is a
complete functional spec of an image-select + telemetry family.

**reCAPTCHA v2 — behaviour-dominant.** It lives across several `google.com` frames plus `about:blank` helper
frames (the anchor + bframe pattern). Its *fingerprint* delta is tiny (`battery`, `storage.estimate`) because it
reads roughly the same canvas/WebGL/etc. surface the collector already does — so the signal isn't the fingerprint,
it's the **behaviour**: an unusually broad input-event net (pointer + mouse + key + `contextmenu` + `keypress` +
focus/blur + `storage`). reCAPTCHA v2 is a mouse/keystroke-telemetry engine with a challenge fallback.

**Turnstile — PoW/behavioural, deliberately light.** With the challenge frame (`challenges.cloudflare.com`) now
probed, it *still* shows no fingerprint or endpoint delta — only `message` (postMessage bridge), `error`, and
`animationend` (the widget lifecycle). This empirically confirms the docs: Turnstile is a proof-of-work +
browser-quirk gate, **not** a canvas/WebGL/audio fingerprinter. The near-empty delta is the finding, not a miss.

**Arkose + GeeTest — interaction-gated (inconclusive).** Both demos rendered only their landing shell — Arkose's
enforcement iframe needs a public key, GeeTest's widget needs a click to spawn. The probe saw the shell's
listeners but never the real challenge frame. These need a **click-then-probe** run to characterize.

## Cross-vendor insights

1. **Behaviour > fingerprint.** Every vendor subscribes to a large input-event set (mouse/pointer/key/focus). Modern
   captchas discriminate more on *how you move and type* than on classic device fingerprint bits.
2. **Classic fingerprinting is table-stakes and mostly already covered.** The signal deltas are small and specific —
   `battery.getBattery`, `storage.estimate`, `webgl.getShaderPrecisionFormat`, `audio.createAnalyser`,
   `screen.pixelDepth`. Kitsune's collector already reads the rest.
3. **Iframe isolation is universal.** Every widget runs in one or more child frames (`challenges.cloudflare.com`,
   `newassets.hcaptcha.com`, the reCAPTCHA bframe). Without the cross-frame merge, *every* delta was empty — it was
   the fix that made this table possible.
4. **Two spectra.** Fingerprint-heavy (hCaptcha) → behaviour-heavy (reCAPTCHA v2) → PoW-light (Turnstile). A faithful
   replica must pick the right point on both axes, not copy a monolith.

## What this feeds — the vendor-profile deltas

**Collector signal additions** (to match the fingerprint-heavy families): `battery.getBattery`, `storage.estimate`,
`webgl.getShaderPrecisionFormat`, `audio.createAnalyser`, `screen.pixelDepth`.

**Behavioural breadth**: broaden the collector's subscribed events toward the observed superset (`contextmenu`,
`DOMMouseScroll`/`mousewheel`, `copy`, `focusin`, `keypress`) where not already covered.

**Protocol shapes**: hCaptcha `checksiteconfig` (sitekey + `sc/swa/spst` flags) + per-widget asset hosts; the rest
from the public-doc specs already gathered (reCAPTCHA `siteverify` `{success, score, action, …}` 120s; Turnstile
`{success, action, cdata, ephemeral_id}` 300s).

## Limitations (and the next tooling steps)

- **Interaction-gated widgets** (Arkose, GeeTest) need a *click-to-trigger* probe mode before their real frame loads.
- **Worker / WASM blind spot** — the probe hooks each frame's main JS; PoW or fingerprinting inside a Web Worker
  (plausibly some of Turnstile's) is not yet captured. Instrumenting `Worker` creation is the fix.
- **Delta is relative to Kitsune** — always read alongside the collector's own coverage, not as an absolute.

## Ethics

Each vendor was probed on the operator's own machine against its public developer demo, a single passive
observation, to spec the mechanism for a vendor-neutral owned reproduction. No solving, no proxying, no lifted
code or assets — consistent with the lab's `TERMS` (reproduce the documented *mechanism*, vendor-neutral).
