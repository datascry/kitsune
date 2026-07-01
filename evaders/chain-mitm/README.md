# chain-mitm — a uTLS MITM front for testing chained tool stacks

`chain-mitm` is a **red-team harness**, not a single evader: a uTLS MITM reverse proxy that forges a browser
TLS+H2 handshake to the edge while a **real browser proxies through it**. Point any browser evader at the
front instead of the edge (`KITSUNE_EDGE=https://chain-front:8444/`) and the edge sees a **forged network
layer + a real JS runtime** — the full-stack chain the catalog describes as hazetunnel+camoufox / Ulixee-Hero
"DoubleAgent" (`docs/evasion-catalog.md:260-261`). Use it to answer: *does chaining a network-forging tool
behind a real browser move the single-session frontier?*

```
real browser  --(its own TLS)-->  chain-mitm front  --(forged uTLS Chrome/Firefox + Go h2)-->  edge
              runs the collector   terminates + re-originates                                  fingerprints
```

`KS_HELLO=chrome|firefox|safari` picks the forged engine. The front POOLS one h2 connection to the edge (as a
real browser does) and forges only the ClientHello — the HTTP/2 SETTINGS/order are Go's, which is the point:
it exposes the integration seam between a forged wire and a real runtime.

## The experiment (2026-07-02) — chaining is counterproductive

Driving the `stealth` evader (real Chromium, collector running) direct vs. through the front, reading the
detector verdict each time:

| Chain config | network layer | coherence tells the chain ADDS | label |
|---|---|---|---|
| real Chromium **direct** (no front) | 0.60 | — (`net.tls_ext_order_static_within_session`, the browser's own) | bot |
| + **Chrome** uTLS front (engine **matched**) | 0.84 | **`net.h2_unknown_vs_ua`** (the Go-H2 seam) | bot |
| + **Firefox** uTLS front (engine **mismatched**) | 0.98 | **`net.tls_vs_ua_browser` + `net.tls_grease_vs_ua` + `net.tls_pq_keyshare_vs_ua` + `net.h2_unknown_vs_ua`** | bot |

**Every chain configuration INCREASED the network score.** A real browser is already its own best network
layer (a coherent Chrome TLS+H2 fingerprint); fronting it with uTLS can only (a) add the Go-H2 seam even when
the engine matches, or (b) detonate the whole coherence matrix when it doesn't. The forged wire and the real
runtime are two tools, and the detector convicts the **seam between them** — the thesis in miniature.

## Why the frontier does not move via tool-chaining

Across every run the dominant conviction was the **browser layer** (0.99–1.0): the headless/CDP automation
tells + the environment floor (`webgl_software`, `voices_empty`, `media_devices_empty`). The network layer is
a rounding error on top, and even the best browser-hardening in the arsenal (`FLOOR_SPOOF`, which fakes voices
+ devices) still scored `bot 0.996` — the detector catches the *spoof* via coherence, not the absence.

So the single-session frontier is bounded by the **browser environment floor + automation layer**, which are
beaten only by **real hardware (GPU/audio/display) + real OS input + a single coherent runtime** (camoufox —
the only evader to ever score `human`), NOT by assembling specialist tools across layers. **The best "chain"
is the least-chained one:** one coherent browser on real hardware. Chaining adds seams; it does not remove
tells. This is the economic bind the lab is built to force — "become a real user on real hardware."

Runs against the allow-listed edge only (`KITSUNE_EDGE`), never a third-party target.
