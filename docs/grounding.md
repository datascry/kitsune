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

| frontier (radar) | capture this | how | unlocks |
|---|---|---|---|
| **Real-traffic prevalence** (X4) | a few hundred+ real-user sessions, **or** the published Berke FP CSV | hosted-demo opt-in export / `corpus/sessions/` from real visitors; **or** the Berke et al. (PoPETs 2025) 8,400-FP `survey-and-browser-attributes-data.csv` (Harvard Dataverse `doi.org/10.7910/DVN/0SGZFF` — accept its research-use terms first) | sessions: `task grounding -- <dir> --build-prior <prior.json>`; Berke CSV: `uv run python -m kitsune_harness.berke_corpus <csv>` | promote `br.fingerprint_improbable` convicting (detection power vs same-distribution injectors) |
| **Coordination IP-reputation / proxy** (X2, X3) | a fleet run through REAL residential/datacenter proxy egress (distinct real exit IPs) | the `KS_PROXY` evader plumbing + real proxy endpoints → `harness/tools/fleet_capture.sh` | `task grounding -- <dir> --expect bot` / `task coordination-live` | convict the proxied/residential fleet (`shared_real_ip` + IP-rep) instead of capping at `candidate` |
| **Device-model ↔ screen geometry** (X5) | real-device fingerprints across models | a real-device matrix or a consented device-fingerprint corpus | add the (device → resolution) map, then `task grounding -- <dir> --expect legit` to FP-check | the DB-dependent half of FP-Inconsistent spatial coherence (the DB-free `br.mobile_no_touch` already shipped) |
| **QUIC / HTTP-3** (ADR-0005) | real Chrome over real QUIC + a QUIC rotation evader | a **browser-trusted cert** (mkcert) host serving the staged `proxy.QUICServer`; a uTLS/quic-go rotation evader | wire `QUICServer` into `ListenAndServe`, then `task grounding` / `coordination-live` | revive `net.quic_*` + ship `net.quic_unstable_within_session` |
| **Real-browser FP audit** (in-sandbox-doable) | real Chrome/Firefox/WebKit captures | `harness/tools/headful_capture.mjs` (Docker Playwright + xvfb) — already used | `task grounding -- <captures> --expect legit` | catch convicting FPs on real browsers the synthetic gate hides (how the v0.74.26-30 FPs were fixed) |

## Capture tooling (already in the repo)

- `harness/tools/headful_capture.mjs` — real headful Chromium/Firefox/WebKit (Docker Playwright + xvfb).
- `harness/tools/fleet_capture.sh` — multi-container concurrent fleet (distinct Docker IPs) — grounds the
  coordination clone tells in-sandbox; swap container IPs for real proxy egress to ground the IP-rep half.
- `harness/tools/chrome_quic_capture.mjs` — real Chrome QUIC ClientHello capture (the QUIC grounding input).

## Discipline (do not shortcut)

- A rule stays `experimental`/unwired until grounded on real data — never promote on a synthetic positive
  (the ADR-0005 QUIC rule and the X-items wait here for exactly this reason).
- Operator raw data is **not committed**; only de-identified aggregates (a rebuilt prior, a verdict report)
  are safe to share. The capture stays on the operator's machine.
- Re-run `task grounding` after any prior/rule change against the same captures — a real browser newly
  scored non-human is a regression, not a catch.
