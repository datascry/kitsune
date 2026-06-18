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

## Run

```sh
docker build -t kitsune-camoufox ./evaders/camoufox    # downloads the Camoufox browser (slow once)
docker run --rm --network kitsune_default \
  -e KITSUNE_EDGE=https://edge:8443/ -e KITSUNE_DETECTOR=http://detector:8080 kitsune-camoufox
```
