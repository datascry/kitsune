# The Coherent Morphing Stack — the research output

This is the single evader configuration the red-team research converges on: **one coherent real browser that scores
`human` across every layer *and* morphs its device identity on demand.** Not a technique in a ladder — the
*composed* stack, documented as the deliverable. Lives in `evaders/stealth/` (`run.mjs` + `devices.json`); its place
in the arms race is the "red frontier" row of [`frontier.md`](frontier.md).

## The thesis, in one line

Per-session detection is **saturated because coherence beats spoofing** — every spoofed field creates a
*disagreement* with another layer, and the detector flags the incoherence, not the value. The only stack that
evades it is one that **is** coherent: a *real* browser whose every layer already agrees. **Morphing then means
swapping a whole coherent identity atomically — never perturbing a field.**

## The stack (bottom-up, each layer neutralising a class of tell)

| Layer | How it's made coherent | Tells it neutralises |
|---|---|---|
| **Transport** (TLS/JA4, HTTP/2) | a *real* browser engine — nothing to spoof | `ja4_*`, `h2_*` static-order / tool-JA4 tells |
| **Runtime** (headful, patchright/camoufox) | real display + CDP-stealth driver | `cdp_runtime_enabled`, `no_chrome_object`, `permissions_anomaly`, `webdriver_*` |
| **Engine ↔ device** (`KS_ENGINE`) | chromium↔Android/desktop-Chrome, webkit↔iPhone/iPad — engine and claimed UA agree | `apple_ua_nonwebkit`, engine-stack incoherence |
| **Device identity** (`KS_DEVICE`) | one tuple (UA + Sec-CH-UA + screen + DPR + touch + isMobile) applied **natively** by the engine — no JS patch, so **no realm-divergence tell** | `ios_screen_oversized`, `ios_dpr_incoherent`, `navplatform_vs_ua`, `ch_ua_version_vs_ua` |
| **GPU / cores / memory** (`devices.json`) | the curated corpus supplies the coherent `webgl_renderer` / `hardwareConcurrency` / `deviceMemory` for the sampled model | `webgl_*`, `mobile_gpu_caps_mismatch`, hardware↔UA incoherence |
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
the launched engine. With `devices.json` wired in, the same draw also fixes `webgl_renderer` + `cores` + `memory`.
Because the whole identity swaps as a unit, **no field can disagree with another** — the property spoofers can't
hold. That is the difference between *morphing* (swap a coherent real identity) and *spoofing* (perturb fields into
incoherence).

## The device corpus — `evaders/stealth/devices.json`

The curated coherence data this research produced, filling the gap in Playwright's registry (which is mobile-heavy
and carries UA/screen/DPR/touch but **no GPU/cores/memory**):

- **17 real tuples** across Windows (5) · macOS (4) · Android (4) · iOS (3) · iPadOS (1), chromium + webkit engines.
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

## Current limits → the next steps this unblocks

1. **Wire `pickDevice` → `devices.json`.** Today the sampler draws from Playwright's registry (UA/screen/DPR only);
   applying the corpus's `webgl_renderer` / `cores` / `memory` coherently **in both the main and worker realms**
   (the realm-divergence traps in `run.mjs` are the hard part) is the next red rung.
2. **Grow + verify the corpus.** Extend `devices.json` toward a comprehensive per-OS generator and confirm each
   tuple with a live capture (the coherence gate above).
3. **The fleet frontier stays external-bound** — residential egress, real-hardware fingerprints, and prevalence data
   are the inputs that would let a fleet of this stack evade coordination too (the buy list in `frontier.md`).
