# Grounding — turning real-world data into shipped detections

Kitsune's standing constraint is that no convicting rule ships without being **grounded**: a faithful
red-team positive **and** a zero-FP sweep. The in-sandbox seams are saturated (see
`docs/detection-catalog.md`, `docs/research-radar.md`); every remaining frontier needs data the sandbox
cannot self-generate — real residential/datacenter **proxy egress**, **real-device** fingerprint diversity,
large-scale **real traffic** for prevalence/IP-reputation, real **QUIC** over a trusted cert. This doc is
the turnkey path: capture that data, run **one command**, and the blocked detections evaluate themselves.

## The one-command sweep

```sh
task grounding -- /path/to/captures --expect legit     # real users  → any non-human is an FP
task grounding -- /path/to/captures --expect bot       # known-bad   → any uncaught session is a miss
task grounding -- /path/to/captures --build-prior ../detector/src/kitsune_detector/data/prevalence_prior.json
```

Captures are **session JSONs** in the collector/edge shape (the same shape as `corpus/sessions/*.json`).
The sweep (`kitsune_harness.grounding`) runs, over the directory:

1. **Per-session verdict** — the FP gate (`--expect legit`) or recall gate (`--expect bot`) against REAL
   traffic, not synthetic browserforge. Misclassifications are listed with the rules that fired.
2. **Coordination grading** (`score_corpus`) — fleets across the captures (a `fleet` on a legit corpus is a
   coordination FP; on a bot corpus it is the catch — a per-session mimic caught at the cluster layer is not
   counted as a miss).
3. **Prevalence-prior rebuild** (`--build-prior OUT`) — rebuilds the prior from the real sessions so
   `br.fingerprint_improbable` gains detection power against generator-sampled fingerprints (Tier-3).

## What each frontier needs (radar X-items → data → command → unlocks)

The **status** column distinguishes a frontier this runbook has already **closed from PUBLIC data**
(grounded, shipped) from one still **external-data-bound** (waiting on data the sandbox cannot self-generate).

| frontier (radar) | status | capture this | how | unlocks |
|---|---|---|---|---|
| **Real-traffic prevalence** (X4) | still-external | a few hundred+ real-user sessions, **or** the published Berke FP CSV | hosted-demo opt-in export / `corpus/sessions/` from real visitors; **or** the Berke et al. (PoPETs 2025) 8,400-FP `survey-and-browser-attributes-data.csv` (Harvard Dataverse `doi.org/10.7910/DVN/0SGZFF` — accept its research-use terms first) | sessions: `task grounding -- <dir> --build-prior <prior.json>`; Berke CSV: `uv run python -m kitsune_harness.berke_corpus <csv>` | promote `br.fingerprint_improbable` convicting (detection power vs same-distribution injectors) |
| **Coordination IP-reputation / proxy** (X2, X3) | still-external | a fleet run through REAL residential/datacenter proxy egress (distinct real exit IPs) | the `KS_PROXY` evader plumbing + real proxy endpoints → `harness/tools/fleet_capture.sh` | `task grounding -- <dir> --expect bot` / `task coordination-live` | convict the proxied/residential fleet (`shared_real_ip` + IP-rep) instead of capping at `candidate` |
| **Device-model ↔ screen geometry** (X5) | still-external | real-device fingerprints across models | a real-device matrix or a consented device-fingerprint corpus | add the (device → resolution) map, then `task grounding -- <dir> --expect legit` to FP-check | the DB-dependent half of FP-Inconsistent spatial coherence (the DB-free `br.mobile_no_touch` already shipped) |
| **Mobile biomech** (X6) | **now-grounded** (public) | nothing to capture — closed off published mobile-biomech corpora | `bh.touch_uniform_velocity` on BrainRun (Zenodo 2598135, CC0; 161,780 swipes / 2,117 devices) + `bh.mobile_keystroke_interval_floor` on Aalto ITE Typing (Zenodo 12528163, CC BY 4.0; 42.3M keystrokes / 849,909 sessions) | shipped — see `docs/mobile-biomech-grounding.md` + `docs/behavioral-data.md` | mobile swipe/keystroke floors (replayed-input tells) the desktop floors miss — **already done** |
| **WebGL renderer↔caps** (G18) | **now-grounded** (public) | nothing external — closed off a live SwiftShader caps probe | `br.webgl_renderer_caps_mismatch`: high-end renderer STRING (RTX / Radeon RX 6000+ / Apple M / Intel Arc) vs `MAX_TEXTURE_SIZE < 16384`, grounded on real headless Chrome's SwiftShader backend (8192, captured live) vs the universal >=16384 high-end floor | `harness/tools/webgl_renderer_spoof.mjs` | catch the source-level WebGL FORK (CloakBrowser/Wayfern/BotBrowser) that patches the renderer string in both realms but cannot change the silicon's caps — **already done** |
| **QUIC / HTTP-3** (ADR-0005) | still-external (**retired** until then) | real Chrome over real QUIC + a QUIC rotation evader | a **browser-trusted cert** (mkcert) host serving the staged `proxy.QUICServer`; a uTLS/quic-go rotation evader | wire `QUICServer` into `ListenAndServe` with **per-CONNECTION** attribution (not per-IP) + full multi-packet CRYPTO reassembly, then `task grounding` / `coordination-live` | revive the two **retired** `net.quic_*` rules (`quic_grease_vs_ua`, `quic_pq_keyshare_vs_ua`) once grounded against a real Chromium QUIC GREASE/PQ positive (ADR-0005) |
| **Real-browser FP audit** (in-sandbox-doable) | **now-grounded** (public) | real Chrome/Firefox/WebKit captures | `harness/tools/headful_capture.mjs` (Docker Playwright + xvfb) — already used | `task grounding -- <captures> --expect legit` | catch convicting FPs on real browsers the synthetic gate hides (how the v0.74.26-30 FPs were fixed) |

> **QUIC is RETIRED, not experimental.** Both `net.quic_grease_vs_ua` (v0.74.32) and
> `net.quic_pq_keyshare_vs_ua` (v0.74.34) were *retired* — they read a per-IP-attributed, partial-reassembly
> QUIC capture that FP-fires on real Firefox, real Brave (Chromium DOES GREASE QUIC), and the most-current
> Chrome (multi-packet PQ ClientHello). `experimental` would not help — an experimental coherence rule still
> convicts; only `retire` stops it firing. Revival is gated on the ADR-0005 **per-connection attribution**
> rebuild above. There is **no** `net.quic_unstable_within_session` rule — the within-session family ships
> with TLS/JA4/IP/h2 + extension-order members (`net.tls_ext_order_static_within_session`, N2), but the QUIC
> member stays infrastructure-blocked behind ADR-0005. (Authoritative status: `docs/detection-catalog.md` /
> `contracts/rules/registry.yaml`.)

## Worked examples this runbook already closed from PUBLIC data

The frontiers above marked **now-grounded** are not aspirational — they were each shipped through this exact
loop, off published data, with no operator capture:

- **X6 — mobile biomech.** `bh.touch_uniform_velocity` and `bh.mobile_keystroke_interval_floor` were
  grounded purely on two open mobile-biomech corpora (BrainRun CC0, Aalto CC BY 4.0): derive the
  human-population percentile, set the floor a margin below the 1st percentile, ship FP-safe with headroom.
  No real-device capture needed — the public corpora *were* the real-device diversity. See
  `docs/mobile-biomech-grounding.md` + `docs/behavioral-data.md`.
- **G18 — WebGL renderer↔caps.** `br.webgl_renderer_caps_mismatch` was grounded on a single PUBLIC fact (a
  live headless-Chrome SwiftShader caps probe: `MAX_TEXTURE_SIZE=8192`) against the universal high-end GPU
  floor (>=16384). The red-team positive is the renderer-spoof evader; the zero-FP side falls out of the
  high-end-string scoping. No external data — the lie betrays itself against the hardware.

## Capture tooling (already in the repo)

Run `ls harness/tools/` for the current set; as of this writing:

- `harness/tools/headful_capture.mjs` — real headful Chromium/Firefox/WebKit (Docker Playwright + xvfb).
- `harness/tools/fleet_capture.sh` — multi-container concurrent fleet (distinct Docker IPs) — grounds the
  coordination clone tells in-sandbox; swap container IPs for real proxy egress to ground the IP-rep half.
- `harness/tools/chrome_quic_capture.mjs` — real Chrome QUIC ClientHello capture (the QUIC grounding input;
  blocked on the ADR-0005 per-connection rebuild before it can revive the retired `net.quic_*` rules).
- `harness/tools/webgl_renderer_spoof.mjs` — renderer-string-spoof-over-SwiftShader positive that grounds
  G18 `br.webgl_renderer_caps_mismatch` (the worked example above).
- `harness/tools/native_lie_ground.mjs` — native-function `toString` / prototype-tamper positive (the
  `*_lie` engine-level tells).
- `harness/tools/css_beacon_ground.mjs` — CSS-only / no-JS beacon capture (the scriptless-collection path).

## Discipline (do not shortcut)

- A rule stays `experimental`/unwired until grounded on real data — never promote on a synthetic positive
  (the ADR-0005 QUIC rule and the X-items wait here for exactly this reason).
- Operator raw data is **not committed**; only de-identified aggregates (a rebuilt prior, a verdict report)
  are safe to share. The capture stays on the operator's machine.
- Re-run `task grounding` after any prior/rule change against the same captures — a real browser newly
  scored non-human is a regression, not a catch.
- For the IP-reputation / proxy frontier (X2/X3), the wire-panel geo/ASN lookup is **keyless** — the
  `geo-refresh` companion pulls DB-IP Lite (CC BY 4.0, no licence key) into `geoip/`; see `docs/deploy.md`
  (§ "Geo / ASN on the wire panel") to stand it up before grounding real proxy egress.
