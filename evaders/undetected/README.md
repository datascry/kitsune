# evaders/undetected — undetected-chromedriver (the most popular anti-detect tool)

[undetected-chromedriver](https://github.com/ultrafunkamsterdam/undetected-chromedriver) (UC) is the
classic Selenium-based anti-detect driver — by far the most widely used. nodriver is its CDP-minimal
successor (separately evaluated). This evader drives it through the edge and scores it.

## Result (live, ruleset 0.24.0)

`bot` 0.999. **Finding:** UC has evolved to defeat the SOTA `Runtime.enable` CDP leak
(`br.cdp_runtime_enabled` does *not* fire) and patches `navigator.webdriver` — so the entire popular
tool ecosystem (UC, nodriver, patchright, rebrowser) has converged on closing the CDP-automation tells.
Only naive plain Playwright still trips `Runtime.enable`. UC remains caught by the **headless-environment
floor** (`webgl_software`, `voices_empty`, `media_devices_empty`) plus `headless_ua` and
`chrome_runtime_missing` — the same wall every Chromium-based tool hits. Same conclusion as nodriver: the
durable signal is the headless *environment*, not the automation surface.

## Run

```sh
docker build -t kitsune-undetected ./evaders/undetected
docker run --rm --network kitsune_default \
  -e KITSUNE_EDGE=https://edge:8443/ -e KITSUNE_DETECTOR=http://detector:8080 kitsune-undetected
```
