# 8. Chromium engine-level renderer spoofing is external-bound

Date: 2026-07-06

## Status

Accepted

## Context

Kitsune's fully-coherent morph profiles are **Firefox-engine only** (camoufox). The blocker for a
Chromium identity — the dominant engine (~65% of real browsers) — is the WebGL renderer string.
camoufox spoofs it at the **engine level** (`webgl_config`, a Gecko C++ value from a fingerprint DB),
so a Chromium morph would need the equivalent. This ADR records a grounded scoping of whether that is
achievable in-sandbox with the current fleet, so we stop re-deriving it.

The detector's WebGL family (`detector/.../demo.py:1904-2051`) catches every JS renderer spoof:
`webgl_getparameter_tampered` (non-native `getParameter`), `webgl_worker_divergence` (the OffscreenCanvas
Worker realm differs), `webgpu_webgl_vs` (the WebGPU adapter exposes the real GPU), and a bare non-`ANGLE (`
string trips `webgl_not_angle`. Under Mesa `llvmpipe` a Chromium reports the **real** `ANGLE (Mesa,
llvmpipe …)` string with correct 16384 caps and **no** tamper/caps tell — but that string trips
`br.webgl_software` (a corroborating environment tell) and is only OS-coherent for a Linux-Chrome UA.

## Decision

**Engine-level Chromium renderer spoofing is not achievable in-sandbox with current tools; it is external.**

Grounded per-tool (2026-07-06): **no** Chromium/Blink anti-detect tool in `evaders/` — stealth
(patchright, rebrowser-playwright), nodriver, zendriver, pydoll, undetected, selenium-driverless, brave —
offers an engine-level renderer override. Each either injects a JS `getParameter` patch (caught) or ships
the renderer honestly from the GL backend. None passes `--use-angle`/`--use-gl`. **ANGLE cannot be made
to report an arbitrary vendor/renderer via flags** — the options select the *backend* and ANGLE derives
the string from that backend's real driver; there is no flag that makes ANGLE emit "NVIDIA GeForce …"
while running on llvmpipe. CDP has **no** renderer primitive. Brave *farbles* (readback noise), it does
not spoof the renderer engine-level, and is caught reference-free.

A fully-coherent hardware-GPU Chromium morph needs **one of**:

1. **Real GPU silicon** — Chromium on an actual GPU, so the honest ANGLE string names a real vendor and
   `webgl_software` never fires. External to the sandbox.
2. **A patched-Chromium engine build** — a source fork overriding ANGLE's renderer string at the C++
   level (the Blink analog of `webgl_config`), reporting `ANGLE (NVIDIA, GeForce …)` while rendering on
   llvmpipe. It must patch **both** the main realm and the OffscreenCanvas Worker (beat
   `webgl_worker_divergence`), keep the `ANGLE (` wrapper (beat `webgl_not_angle`), and pair with
   llvmpipe's real 16384 caps (beat the allocation probe). **This binary does not exist in the fleet** and
   would have to be built.

## Consequences

- The in-sandbox ceiling for a Chromium morph is **"coherent-except-`webgl_software`"**: with llvmpipe +
  a Linux-Chrome UA, every renderer/caps/tamper tell is silent and the sole GPU residual is the single,
  non-convicting `webgl_software` environment tell. This is a legitimately-evading identity (it cannot be
  *convicted* on GPU), just not a hardware-GPU one.
- **Fully-coherent hardware-GPU morphs remain camoufox/Firefox-only** in-sandbox. The morph-profile
  registry's fully-coherent tier is the 3 Firefox×OS identities; a Chromium/WebKit entry would carry the
  `webgl_software` note.
- This bounds the diffuse-fleet frontier too (ADR-adjacent): distinct *coherent* TLS builds are finite
  in-sandbox (few real engines), which is the "distinct builds" economic wall made concrete — see the
  coordination frontier.
- **Do not re-grind** JS renderer spoofs or ANGLE-flag hunts; the next move is either real silicon or a
  patched-Chromium binary, both external.

## References

- `evaders/stealth/run.mjs:390-399` (the in-code analysis), `evaders/camoufox/run.py:379-393` +
  `patch_webgl_db.py` (the Firefox-only engine-level reference), `docs/research-radar.md` GROW-REGISTRY
  rungs 2-3, `docs/frontier.md` (Chromium/WebKit full GPU coherence = external-hardware-bound).
