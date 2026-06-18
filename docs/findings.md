<!-- docs/findings — empirical results from running the evader fleet against the detector. -->
<!-- The arms-race ladder, what each anti-detect tool leaks, and the durable signals. -->

# Findings

What Kitsune has actually measured, running each evader through the live edge → detector. The thesis
holds: **incoherence across layers, not any single bad signal, is what survives anti-detect tooling.**

## The arms-race ladder

Each rung defeats the rung below; the detector answers each with a new cross-layer check.

| Evader | Class | Live verdict | What betrays it |
| --- | --- | --- | --- |
| `vanilla` (httpx) | scripted HTTP | `bot` | no browser layer at all; datacenter ASN |
| `stealth-naive` (Playwright) | headless Chromium | `bot` | `navigator.webdriver`, headless UA, no `window.chrome` |
| `stealth-patched` / `full-stealth` | JS-patched stealth | `bot` | software WebGL, permissions anomaly, plugin/UA incoherence |
| `spoof-ua` | UA forgery on Chromium | `bot` | Firefox UA on a Chromium engine — `vendor`/`productSub`/render contradict the UA |
| `patchright` | CDP-patched Playwright | `bot` | removes the *automation* surface, but the headless **environment** fingerprint remains |
| `nodriver` | undetected-chromedriver heir | `bot` (0.94) | same: no webdriver flag, but headless-container environment betrays it |
| **`camoufox`** | **engine-level (C++) spoof** | **`suspicious` (0.40)** | **coherent at the JS layer — only WebGL2 absence leaks** |

**Takeaway for the chromium tools:** removing the automation/webdriver surface does nothing for the
durable signal. Every Chromium-based tool runs headless Chromium in a container, and the *environment*
fingerprint (software WebGL, missing GPU, absent `window.chrome` surface) gives it away regardless of
how thoroughly the webdriver flag is hidden.

## Camoufox is the frontier

Camoufox spoofs at the engine level (C++), not via injected JS, so its lies are internally coherent in
ways patched-Chromium tools cannot match:

- **navigator.* coherence** — `platform`, `oscpu`, `vendor`, `userAgent`, `productSub`, render engine all
  agree on one OS/browser. The whole v0.7–0.10 OS-coherence battery (`navplatform_vs_ua`,
  `oscpu_vs_ua`, `vendor_vs_ua`, `productsub_vs_ua`) finds nothing — every value is consistent.
- **Per-launch randomization** — OS and hardware vary per instance (Windows/macOS, 8/12/32 cores) so no
  two instances look alike at the JS layer.
- **Font-metric spoofing (confirmed 2026-06-18)** — Camoufox spoofs Canvas `measureText` font metrics to
  match its claimed OS. An instance claiming macOS returns macOS-signature font widths (Helvetica Neue,
  Menlo, …) despite running on a Linux container, so the classic CreepJS/fingerprintjs **font-OS probe
  (`br.font_os_vs_ua`) is defeated** — the measured font OS coherently matches the claimed platform.

The single per-session leak that remains: **`br.webgl2_missing`** — headless Camoufox exposes no WebGL2
context, where a real desktop browser does. A determined adversary running headful (or spoofing a WebGL2
context) closes even this. Per-session detection of a coherent engine-level spoof is, at the limit, a
losing game.

## The durable signal: coordination, not the instance

A *single* Camoufox session can be made arbitrarily coherent. A *fleet* cannot hide that it shares an
identity below the spoofing layer:

- All instances of a fleet share one **JA4** — the TLS handshake is the engine's, and anti-detect tools
  spoof JS, not the TLS stack. (JA3 is not stable across the GREASE randomization; JA4 is.)
- The instances deliberately **randomize their JS identity** (hardware, platform) to look like distinct
  users.

`harness/coordination.py` grades a JA4 cluster on three independent coordination signals:

1. **JS-divergence paradox** — TLS-identical but JS-divergent. A genuine same-build cohort that shares a
   JA4 also shares its JS identity; only a spoofing fleet shows one TLS fingerprint under many JS
   identities. This is the primary discriminator (a homogeneous JA4 cluster never reaches `fleet`).
2. **Timing lockstep** — fleet instances launch together. Members sharing a JA4 that all arrive inside a
   2-minute window are synchronized; organic same-JA4 users are spread over hours.
3. **Volume** — more members in the cluster raises confidence.

The live Camoufox fleet scores **`fleet` 1.00**: shared JA4, JS divergent across all three instances
(hardware 8/12/32, platform Windows/macOS), and all three arriving within 20 seconds.

This is the signal that matters for the bots/DDoS domain: an attacker fielding thousands of coherent
anti-detect browsers still routes them through a shared engine/TLS stack, and the coordination is visible
in aggregate even when every instance is individually perfect.

## Testing strategy (efficiency)

Re-running the seven known-caught evaders every iteration teaches nothing. Testing is tiered:

- **Frontier tier** (`scripts/frontier.sh`, every iteration) — only the evaders that still beat
  per-session detection: Camoufox single + a Camoufox fleet. Fast; this is where detection still loses.
- **Regression tier** (`scripts/live_scoreboard.sh`, sparse) — the full known-caught fleet, run
  occasionally to confirm no regression.
