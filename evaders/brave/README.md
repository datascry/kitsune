# evaders/brave — Brave (the farbling browser)

[Brave](https://brave.com) defends fingerprinting by **farbling**: injecting per-session, per-eTLD+1
pseudo-random noise into canvas / audio / WebGL readback, so the fingerprint differs every session.
This is a distinct philosophy from Camoufox (coherent uniqueness) and Tor (RFP uniformity). Driven via
Playwright's `executablePath`.

## Result (live, ruleset 0.26.0)

`bot` 1.0. **Farbling is caught reference-free:** `br.canvas_noise` fills a canvas with a solid colour
and reads it back — a real browser returns the exact colour, Brave's farbling perturbs pixels. (The
per-render `audio_noise` probe does *not* fire — Brave's audio farbling is per-session *deterministic*,
so two renders match; the solid-fill canvas invariant is what exposes it.) Driven by Playwright it is
also `webdriver=true` + headless, so automation and environment tells catch it too. A *human* on real
Brave would trip only `canvas_noise` (weight 0.5 → `suspicious`, an elevated-risk privacy-tool signal,
not a bot conviction).

## Run

```sh
docker build -t kitsune-brave ./evaders/brave
docker run --rm --network kitsune_default \
  -e KITSUNE_EDGE=https://edge:8443/ -e KITSUNE_DETECTOR=http://detector:8080 kitsune-brave
```
