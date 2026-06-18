# evaders/stealth — anti-detect browser evader (Playwright, real)

Status: **live** ✅ — drives a real Chromium through the edge and is scored by the detector. Runs in
the official Playwright Docker image (no local browser needed).

## What it does

Launches Chromium, navigates the edge (which fingerprints the TLS handshake + serves the collector
page), moves the pointer, lets the in-page collector post browser+behavioral signals, then reads the
verdict back by `ks_sid`. Two modes:

- **naive** — plain automation; leaks `navigator.webdriver` and a HeadlessChrome UA.
- **stealth** (`STEALTH=1`) — patches `navigator.webdriver` and presents a real Chrome UA.

## Measured result (real browser, live stack)

| mode | browser score | label | contradictions |
|---|---|---|---|
| naive | **0.985** | bot | `br.webdriver_present`, `br.headless_ua` |
| stealth | **0.00** | human | none |

The detector catches naive automation; the stealth evader defeats the browser layer. This is the
`vanilla → naive → stealth` arms-race story, end-to-end.

## Run

```sh
docker compose up -d --build detector edge
docker run --rm --network kitsune_default \
  -e KITSUNE_EDGE=https://edge:8443/ -e KITSUNE_DETECTOR=http://detector:8080 \
  -v "$PWD/evaders/stealth":/work -w /work \
  mcr.microsoft.com/playwright:v1.48.0-jammy \
  bash -c "npm i -s playwright@1.48.0; node run.mjs; STEALTH=1 node run.mjs"
```

## Next (phase 3)

Swap Chromium for **Camoufox** (C++-level fingerprint spoofing) + **patchright** (CDP-leak patching)
+ **ghost-cursor**/human-typing, per `docs/catalog.md` §7 — to also beat deeper fingerprint and CDP
checks, not just the `webdriver`/UA tells.
