# The Coherent Morphing Stack — the research output

This is the configuration the red-team research converges on: **one coherent real browser that scores `human` across
every layer *and* morphs its identity on demand.** Not a technique in a ladder — the *composed* stack, documented as
the deliverable. It is **composed from the fleet, the right tool per layer** — no single evader does it all:
`evaders/stealth` (native UA/screen/DPR + CDP model/CH metadata + provisioning + humanized input), **`camoufox`**
(engine-level renderer / canvas / font spoofing — patched *natively*, where `stealth`'s JS patches get caught), and
**`os-spoof`** (the TCP SYN kernel, for cross-OS morphs). The device corpus is `evaders/stealth/devices.json`. Its
place in the arms race is the "red frontier" row of [`frontier.md`](frontier.md).

## The thesis, in one line

Per-session detection is **saturated because coherence beats spoofing** — every spoofed field creates a
*disagreement* with another layer, and the detector flags the incoherence, not the value. The only stack that
evades it is one that **is** coherent: a *real* browser whose every layer already agrees. **Morphing then means
swapping a whole coherent identity atomically — never perturbing a field.**

## The stack (bottom-up, each layer neutralising a class of tell)

| Layer | How it's made coherent | Tells it neutralises |
|---|---|---|
| **Transport** (TLS/JA4, HTTP/2) | a *real* browser engine — nothing to spoof | `ja4_*`, `h2_*` static-order / tool-JA4 tells |
| **Network / OS kernel** (`os-spoof` proxy) | forges the TCP SYN kernel fingerprint (userspace stack over `AF_PACKET`, `NET_RAW`+`NET_ADMIN`) so the kernel the SYN reveals matches the claimed OS — route the browser through `KS_PROXY=socks5://os-spoof:1080` | `tcp_os_vs_ua` (cross-OS) |
| **Runtime** (headful, patchright/camoufox) | real display + CDP-stealth driver | `cdp_runtime_enabled`, `no_chrome_object`, `permissions_anomaly`, `webdriver_*` |
| **Engine ↔ device** (`KS_ENGINE`) | chromium↔Android/desktop-Chrome, webkit↔iPhone/iPad — engine and claimed UA agree | `apple_ua_nonwebkit`, engine-stack incoherence |
| **Device identity** (`KS_DEVICE`) | one tuple (UA + Sec-CH-UA + screen + DPR + touch + isMobile) applied **natively** by the engine — no JS patch, so **no realm-divergence tell** | `ios_screen_oversized`, `ios_dpr_incoherent`, `ch_ua_version_vs_ua` |
| **Model + UA-CH brands** (CDP `setUserAgentOverride`) | the browser's own `userAgentMetadata` (model, platform, clean brands) set natively in both realms | `mobile_no_js_model`, `ch_ua_mobile_no_model`, `ch_he_headless` |
| **GPU renderer string / canvas / fonts** (engine-level: `camoufox` / source-fork) | patched **natively** across both realms — *not* a JS getter override, so no tampering/`worker_vs_main` tell (a `stealth` addInitScript patch **is** caught; camoufox is not) | `webgl_renderer_artifact`, `canvas_lie`, `font_os_vs_ua` (the string layer) |
| **GPU caps** (Mesa `llvmpipe` — `KS_LLVMPIPE`) | **falls in software** — llvmpipe reports AND allocates `MAX_TEXTURE_SIZE` 16384 (RAM-backed, so the allocation probe passes), paired with a camoufox renderer whose DB caps are a coherent 16384. No GPU. Grounded 2026-07-05: every caps tell silent | `webgl_renderer_caps_mismatch`, `webgl_maxtexture_unallocatable`, `mobile_gpu_caps_mismatch` |
| **Mobile core count** (real cores) | *host-bound* — `hardwareConcurrency` can't be lowered (JS caught, `--cpuset-cpus` ignored → stays the host's count); desktop tuples are core-coherent, **mobile** morphs need ≤8-core hardware | `mobile_cores_high` |
| **Provisioned floor** (`KS_PROVISION`) | audio / voices / webrtc present, as a real device has | `voices_empty`, `media_devices_empty`, empty-realm tells |
| **Behaviour** (`KS_HUMANIZE` / `HUMAN_MOUSE`) | bézier mouse + paced, jittered timing | `input_entropy_floor`, `no_input_before_action`, cadence floors |

The point of the table: coherence is **compositional** — each layer must agree with the ones above and below. A
patched browser breaks one seam; a real, natively-configured browser breaks none.

## Morph on demand — the atomic swap

```sh
# one coherent identity, resampled every launch/session:
KS_ENGINE=chromium KS_DEVICE=random KS_PROVISION=1 KS_HUMANIZE=1  node run.mjs
KS_ENGINE=webkit   KS_DEVICE=random ...                          # iOS slice (coherent Safari)
KS_DEVICE=list                                                   # enumerate the corpus for this engine
KS_DEVICE="MacBook Pro 14 (M3)"                                  # pin a specific identity
```

`KS_DEVICE=random` draws **one whole tuple** and applies UA + screen + DPR + touch + isMobile **together**, scoped to
the launched engine, and CDP metadata sets the model + CH brands natively. Because the identity swaps as a unit,
**no field can disagree with another** — the difference between *morphing* (swap a coherent real identity) and
*spoofing* (perturb fields into incoherence). The GPU renderer *string* is swapped at the **engine level** (camoufox
/ source-fork), not by a JS patch; the GPU *caps* and *core count* are physical and follow the host hardware (see the
boundary below).

## The device corpus — `evaders/stealth/devices.json`

The curated coherence data this research produced, filling the gap in Playwright's registry (which is mobile-heavy
and carries UA/screen/DPR/touch but **no GPU/cores/memory**):

- **18 real tuples** across Windows (5) · macOS (4) · Android (5) · iOS (3) · iPadOS (1), chromium + webkit engines,
  each tagged with its `max_texture_size` tier (8192 low-end vs 16384 flagship — the GPU-caps coherence gate).
- Each carries the **verified** `webgl_renderer` (exact `UNMASKED_RENDERER_WEBGL` string per GPU), plus
  `hardwareConcurrency` and `deviceMemory` under the documented Chrome rules (memory capped at 8 + quantized;
  undefined on iOS; ANGLE-wrapped renderer strings per platform).
- **Coherence gate:** screen/DPR/webgl are from verified public sources and cores/memory follow the documented caps,
  but every tuple should be **confirmed against a live headful capture** (`harness/tools/headful_capture.mjs`) before
  a live engagement. The DB is the curated starting corpus; the capture is the coherence gate. Sources + the full
  coherence rules are in the file's `_meta`.

## What it achieves — and what it doesn't (grounded)

- **Per-session: scores `human`.** The saturated fingerprint layer is evaded by construction — there is no
  incoherence to flag on a real, coherently-morphed browser. This is the whole point: you cannot out-detect a real
  browser per-session.
- **Behaviour: lives in the band.** The humanized mouse/timing sits inside the wide, permanent human band (see
  `session-intent-axis-closed`).
- **It does NOT beat coordination.** A *fleet* of these still shares a build and a humanizer-descriptor cluster; it
  converts to `campaign` unless the fleet is externally clean (distinct builds · real-hardware fps · clean
  residential egress · Poisson-staggered). That fully-clean diffuse fleet is **the frontier**, external-data-bound —
  see [`frontier.md`](frontier.md) and `coordination-axis-closed`.

## The in-sandbox coherence boundary (GROUNDED — the wiring loop ran to close)

The 6-rung coherent-morphing-stack loop (see `docs/research-radar.md`, memory `coherent-morph-boundary`) wired what is
coherently morphable and mapped every wall. The governing result:

- **Native mechanisms morph coherently.** Playwright device (UA/screen/DPR/touch) and **CDP `userAgentMetadata`**
  (model + CH brands) close their tells with no divergence — the model wiring is the one clean in-sandbox win.
- **`stealth`'s JS patches are caught — but engine-level browsers are not.** Via `stealth` (Playwright addInitScript):
  a `getParameter` renderer patch → `webgl_getparameter_tampered` + `webgl_worker_vs_main` + `webgpu_webgl_vs`; a
  Worker-wrap → `worker_source_rewritten` + `worker_constructor_tampered`; a `getHighEntropyValues` model wrap →
  `uadata_model_worker_divergence`. **But that is a `stealth` limitation, not fundamental** — `camoufox` (Firefox
  source-level) and Brave (farbling) patch the renderer string / canvas / fonts **natively** across both realms, so
  those tampering/`worker_vs_main` tells can't see them. **Grounded live (2026-07-05):** camoufox macOS (headful) →
  `webgl_getparameter_tampered` + `webgl_worker_vs_main` + `webgpu_webgl_vs` + `webgl_software` + `canvas_lie` **all
  silent**; the only GPU tell left is `webgl_renderer_caps_mismatch` — the durable caps wall (#1). So the engine-level
  fields **are** coherently morphable — with the right tool.
  You cannot *JS-patch* coherence; you compose a browser that is already coherent.
- **The cross-OS TCP kernel is SOLVED — compose `os-spoof`.** A cross-OS morph trips `net.tcp_os_vs_ua` (the SYN
  option order reveals the container's Linux kernel), but the **`os-spoof` evader** (`KS_MODE=proxy`) forges the SYN
  via a userspace TCP stack (`NET_RAW`+`NET_ADMIN`, both available in-sandbox) and routes the real browser through it.
  **Grounded live:** the iOS morph via `KS_PROXY=socks5://os-spoof:1080 KS_PROFILE=ios-safari` → `tcp_os_vs_ua`
  **silent**. So the composed cross-OS node is `stealth`(device) + `os-spoof`(kernel). Residuals: `net.tls_grease_vs_ua`
  (the browser's *own* TLS ≠ the claimed OS's — a uTLS front [`chain-mitm`] only trades it for the Go-h2 seam
  `h2_unknown_vs_ua`, so it needs a **native-TLS-matching browser**, real-browser/build-bound) and **deep TCP
  behaviour** (window/retransmit dynamics — a happy-path userspace stack doesn't reproduce; production = gVisor
  netstack). iOS/webkit is the cleanest target (Safari exposes less → sidesteps the Android GPU/cores/model walls).
- **The GPU *caps* and *core count* are real-silicon-bound.** The renderer string morphs at the engine level (above),
  but the no-GPU container's software GL has `MAX_TEXTURE_SIZE` 8192 (< the 16384 floor real GPUs expose) → the
  **caps mismatch is the durable catch no string spoof fixes**; and `hardwareConcurrency` can't be lowered (`stealth`
  JS caught, `--cpuset-cpus` ignored → stays the host's count), so desktop tuples are core-coherent but mobile need
  ≤8-core hardware.

### The residuals — and NONE is a true hardware wall (the GPU caps wall fell)

Composing the right tool per layer closes far more than any single evader. What was called "the one true hardware
wall" — GPU caps — **fell in software (2026-07-05)**. What actually remains is smaller and none of it is a GPU:

1. **GPU caps — FELL, in software, no GPU.** `MAX_TEXTURE_SIZE` 8192 was **SwiftShader's default**, not hardware.
   Mesa **`llvmpipe`** (already on disk, RAM-backed) reports AND *allocates* 16384; paired with a camoufox renderer
   whose DB caps are a coherent 16384 (`KS_LLVMPIPE`), **every caps tell goes silent** — including the allocation
   probe `webgl_maxtexture_unallocatable`, which passing proves it is *real*, not a value lie. Grounded live. The
   only residue here is **camoufox's mac fingerprint data** (its Apple-M1 entry has a buggy 8192; a macOS morph needs
   the DB corrected) and the **mobile core count** (host-bound) — a data fix and a resource limit, not a wall.
2. **Deep TCP behaviour — a live blue tell that os-spoof *passes* on a normal morph.** The detector already ships the
   deep-TCP tells: `net.tcp_static_window` (w0.4, corroborating — a real kernel auto-tunes its receive window; a
   hardcoded one is static) and `net.tcp_syn_anomaly` (the SYN wscale *value*), both built against the os-spoof
   forger. **But `tcp_static_window` is FP-conservative** (fires only on a sizable ≥12-segment static flow), and
   **grounded 2026-07-05: a full stealth-chromium flow through an os-spoof proxy leaves all deep-TCP tells silent** —
   the happy-path stack *passes* a normal browser morph. So gVisor `netstack` (real window auto-tuning) is the red
   counter *only for long/sizable static sessions* — a **major** build for a marginal, corroborating, long-session
   gain. Deferred as a production-robustness upgrade, not a current-morph need.
3. **Cross-OS native TLS — real-*target-OS* browser, not silicon.** The residual `tls_grease_vs_ua` is only that our
   in-sandbox browser (Playwright's Linux WebKit) isn't the target OS's build; fronting it with a uTLS MITM
   (`chain-mitm`) is counterproductive (adds the Go-h2 seam). Running the **actual target-OS browser** (real macOS
   Chrome / iOS Safari) makes its native ClientHello the OS's by construction — a real-OS host, not GPU hardware.

So the true terminus has **no in-sandbox hardware wall left.** The GPU caps wall fell in software; and a
**Linux-target morph is now FULLY coherent in-sandbox** — native TLS (Linux), native kernel (Linux), `llvmpipe`
16384 GPU caps, engine-level renderer. Everything morphs coherently with the right tool: UA/screen/DPR/model+CH
(`stealth` + CDP), renderer string/canvas/fonts + coherent GPU caps (`camoufox` + `llvmpipe`), the TCP kernel
(`os-spoof`). What remains is **not hardware**: a *cross-OS* morph still needs the target-OS browser for native TLS
(a real-OS requirement, moot for a Linux target); camoufox's mac fingerprint data has a buggy 8192 cap (a DB fix);
the mobile core count is host-bound; and the fleet frontier stays external-data-bound (the buy list in
`frontier.md`). Minor follow-ups: `navigator.platform` on the iOS morph; a codec-enabled real Chrome for
`codec_os_incoherent` on non-Linux UAs.
