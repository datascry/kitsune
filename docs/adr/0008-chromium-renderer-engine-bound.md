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

## Grounded 2026-07-06: the `LD_PRELOAD` native-interception shortcut does NOT work

A tempting cheaper-than-a-fork idea: `LD_PRELOAD` a shim that rewrites the native `glGetString(GL_RENDERER/
GL_VENDOR)` so ANGLE (under `--use-gl=angle --use-angle=gl` on Mesa llvmpipe, headful) reports a hardware
GPU **natively** (no JS patch → no tamper/worker tells). Prototyped and grounded against stealth-Chromium;
it **fails** at three escalating interposer levels:
1. **PLT interpose `glGetString`** — the shim loads in all 9 Chromium processes (`LD_PRELOAD` propagates
   fine with `--no-sandbox`), but `glGetString(RENDERER/VENDOR)` is **never called** through it. Renderer
   unchanged (`ANGLE (Mesa, llvmpipe …)`).
2. **Hook the resolvers** `eglGetProcAddress` / `glXGetProcAddress[ARB]` — never invoked for `glGetString`
   either. ANGLE resolves the native GL entry points through neither the PLT nor the public resolvers.
3. **Hook `dlsym` itself** (the only remaining path — a `dlopen(libGL)+dlsym` handle lookup bypasses 1+2) —
   **breaks Chromium startup** (dlsym is universal; interposing it destabilizes node+Chromium; the probe
   produced no render at all).
So ANGLE reaches Mesa's renderer string via an internal/handle path that a userspace preload cannot
cleanly reach, and the one hook that could is too invasive to survive. The "cheap shim" does not exist —
coherent Chromium needs a **real build**: a patched Mesa llvmpipe (rename `GL_RENDERER` at the driver, a
Mesa rebuild) or a patched Chromium/ANGLE. Both external. This **reinforces** the decision above.

## Scoped path if pursued: patch Mesa llvmpipe (not Chromium)

Grounded scope (2026-07-06). The renderer string ANGLE reports is `ANGLE (<GL_VENDOR>, <GL_RENDERER>, OpenGL
<ver>)` where the inner fields come from the **Mesa llvmpipe driver**, not from Chromium. So the leverage point
is Mesa, and the fix is a **tiny driver patch**, not a browser fork.

- **Where:** Mesa 23.2.1 in the stealth image; llvmpipe compiles into `swrast_dri.so`. The strings come from
  `src/gallium/drivers/llvmpipe/lp_screen.c` — `llvmpipe_get_name()` (→ `"llvmpipe (LLVM …)"` = GL_RENDERER) and
  the screen's vendor getters (→ `"Mesa"` = GL_VENDOR). NB the `webgl_software` rule matches
  `/swiftshader|llvmpipe|software|mesa/i`, so BOTH the renderer AND the vendor must lose their Mesa/llvmpipe
  tokens — patch both.
- **The patch (elegant form):** make `get_name`/`get_vendor` honor an **env override** (e.g.
  `KS_GL_RENDERER` / `KS_GL_VENDOR`), defaulting to the real strings. Then a Linux-Chrome node sets
  `KS_GL_RENDERER="NVIDIA GeForce GTX 1080/PCIe/SSE2"`, `KS_GL_VENDOR="NVIDIA Corporation"` → ANGLE reports
  `ANGLE (NVIDIA Corporation, NVIDIA GeForce GTX 1080/PCIe/SSE2, OpenGL 4.5)`. ~3 string returns.
- **Build + inject:** Mesa builds with meson+ninja against LLVM 15; a Dockerfile stage clones Mesa 23.2, applies
  the patch, builds the swrast target, copies `swrast_dri.so` over the image's `/usr/lib/x86_64-linux-gnu/dri/`
  (or point `LIBGL_DRIVERS_PATH` at it). ~10–20 min build; deps are apt-gettable.
- **Why it beats a Chromium fork:** it's **engine-agnostic** — one driver patch makes *every* browser on
  llvmpipe (stealth-Chromium AND stealth-WebKit) report the coherent renderer, natively, in all realms (it's
  below JS, so no `getparameter_tampered` / `worker_divergence`), with the real 16384 caps. Env-configurable →
  distinct GPUs per fleet node. Mesa churns ~quarterly and the patch (three static strings) rebases trivially —
  nothing like Chromium's monthly-rebase treadmill.
- **What clears vs residual caveats:** clears `webgl_software`, `webgl_renderer_caps_mismatch`, the tamper/worker
  family → a coherent hardware-GPU Chromium/WebKit. Caveats to handle: the GL_VERSION string still reads
  `Mesa 23.2.1` (patch it too, or accept a mild version-vs-renderer tell — check whether the detector reads it);
  and if WebGPU is ever enabled (Vulkan/lavapipe) its adapter is a *separate* identity that a GL-only patch
  leaves mismatched (grounded: default stealth doesn't expose it, so not a factor today — but patch lavapipe's
  device name too if WebGPU is turned on). The renderer must stay OS-coherent (a Linux GPU string under a
  Linux-Chrome UA; never an Apple/Windows string).
- **Verdict:** feasibility HIGH, effort MODERATE (~1 day: patch + Mesa build stage + inject + ground), value
  MODERATE-HIGH (unlocks coherent Chromium *and* WebKit — the two engines the registry lacks — per-node
  configurable). It is the **least-bad** in-sandbox path to non-Firefox coherence, well below a Chromium fork.
  Still a custom driver build to carry, so pursue only if Chromium/WebKit coherence is worth that upkeep;
  otherwise it stays parked as the documented plan.

## Outcome (grounded 2026-07-06): the Mesa patch WORKS for WebGL; WebGPU is env-bound

The scoped Mesa-patch path was BUILT and GROUNDED, and it **overturns this ADR's "external-bound" verdict for the
WebGL renderer.** A patched Mesa 23.2.1 llvmpipe (`evaders/stealth/mesa-patch/build.sh`) whose `lp_screen.c`
honors `KS_GL_RENDERER`/`KS_GL_VENDOR` makes Chromium/ANGLE report a hardware GPU **natively** — grounded at three
levels (glxinfo, Chromium WebGL, the detector): `webgl_software`, `webgl_renderer_caps_mismatch`,
`getparameter_tampered`, `worker_vs_main` **all silent**, 16384 caps, no JS spoof. Two build gotchas solved: the
`xcb-shm` dep, and libGL's DRI **version-string check** (stamp the base image's exact Mesa version + drop `.git`).

**The one residual — `webgpu_webgl_vs` (w0.7) — is environment-bound, not a patch problem.** It fires because
"WebGL claims a hardware GPU but WebGPU exposes no real adapter" (the stealth image ships no Vulkan loader, so
Dawn gets a null adapter). Building Mesa **lavapipe** (the Vulkan software driver) proved the same `lp_screen.c`
patch flows through — `vulkaninfo` reports `deviceName = NVIDIA GeForce GTX 1080…`. But making **Dawn actually use**
the software lavapipe adapter (loader + ICD + `--ignore-gpu-blocklist --enable-features=Vulkan`) **hangs headful
Chromium** in this xvfb/software environment (5+ min, no verdict). So a Chromium morph is
**coherent-except-`webgpu_webgl_vs`** in-sandbox; closing that last tell is gated on a stable Dawn+lavapipe path
(a real GPU-less deployment with the loader/ICD baked in and Vulkan stable) or real silicon — genuinely external.

**Net:** coherent Chromium WebGL is now in-sandbox via a ~3-line Mesa patch (engine-agnostic — it also fixes
stealth-WebKit); the last GPU tell is env-bound. The value-proposition analysis + scope held up; the fork was never
needed.

## References

- `evaders/stealth/run.mjs:390-399` (the in-code analysis), `evaders/camoufox/run.py:379-393` +
  `patch_webgl_db.py` (the Firefox-only engine-level reference), `docs/research-radar.md` GROW-REGISTRY
  rungs 2-3, `docs/frontier.md` (Chromium/WebKit full GPU coherence = external-hardware-bound).
