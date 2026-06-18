# evaders/camoufox — engine-level anti-detect browser (Camoufox)

Status: **under evaluation.** [Camoufox](https://github.com/daijro/camoufox) is a Firefox fork that
spoofs fingerprint vectors at the **C++ implementation level** (below the JS API surface), so it
leaves none of the JS-tampering tells that catch injection-based stealth. This evader drives it
through the edge and scores it on the same matrix as the chromium tools.

## Hypothesis

The chromium evaders (naive, manual-stealth, full-stealth, patchright) are all caught by the
*headless-environment* fingerprint (software WebGL, permissions anomaly, missing `window.chrome`, no
plugins). Camoufox is a different engine (Firefox) with engine-level spoofing, so most of those
Chrome-specific tells should not apply — testing whether an engine-level browser slips the floor that
catches every chromium-based tool.

## Result (live)

**Camoufox evades the entire ruleset — `0/27`, `human`.** The only browser evader to score human,
alongside vanilla httpx. It wins because it is a different engine with engine-level spoofing:

- Firefox UA → the Chrome-specific tells don't apply (`window.chrome`, ANGLE WebGL, the Chrome
  permissions quirk), and there is no `navigator.userAgentData`, so the Client-Hints checks can't fire.
- It exposes **no WebGL renderer** (Firefox `resistFingerprinting` blocks `WEBGL_debug_renderer_info`),
  so `webgl_software` / `webgl_os_vs_ua` get no input.
- `navigator.webdriver = false` at the engine level — no JS-tampering tells.
- A coherent spoofed fingerprint (it claims `ua_platform = macOS` on a Linux host, with plausible
  `hardwareConcurrency` and plugins).

Two findings: (1) engine-level spoofing is the cutting edge — it defeats the JS-surface ruleset
entirely; (2) **the ruleset is Chrome-biased**.

**Follow-up (v0.7.0):** added `br.navplatform_vs_ua` (engine-agnostic — `navigator.platform` vs the UA
platform, no Client-Hints needed). Camoufox **also** evades it: it spoofs `navigator.platform` to
`MacIntel` (macOS), coherent with its macOS UA. So engine-level spoofing buys not just surface
plausibility but **cross-vector coherence** — defeating the coherence detectors that catch the
chromium tools' partial spoofs. The realistic counters left are a Camoufox-specific inconsistency (an
arms race against its updates) or **behavioral / coordination** signals, which no fingerprint spoof
addresses. The `navplatform_vs_ua` rule still catches *incoherent* platform spoofs (e.g. a Windows UA
on a real Linux `navigator.platform`).

## Run

```sh
docker build -t kitsune-camoufox ./evaders/camoufox    # downloads the Camoufox browser (slow once)
docker run --rm --network kitsune_default \
  -e KITSUNE_EDGE=https://edge:8443/ -e KITSUNE_DETECTOR=http://detector:8080 kitsune-camoufox
```
