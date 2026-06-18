# evaders/nodriver — CDP-based anti-detect (undetected-chromedriver successor)

[nodriver](https://github.com/ultrafunkamsterdam/nodriver) drives Chrome directly over CDP with no
Selenium/webdriver and a minimal CDP footprint. This evader runs it through the edge and scores it.

## Result (live)

`bot` — browser layer **0.94** (headless-environment tells: software WebGL, permissions anomaly,
missing `window.chrome`, no plugins). nodriver removes the *automation* surface (no webdriver flag)
but, like patchright, it runs headless Chromium in a container, so the **environment fingerprint
still betrays it**. Same conclusion as every chromium-based tool: the durable signal is the headless
environment and (for a fleet) the shared TLS identity, not the webdriver flag.

## Run

```sh
docker build -t kitsune-nodriver ./evaders/nodriver
docker run --rm --network kitsune_default \
  -e KITSUNE_EDGE=https://edge:8443/ -e KITSUNE_DETECTOR=http://detector:8080 kitsune-nodriver
```
