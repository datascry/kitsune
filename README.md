# Kitsune — a bot detection ⇄ evasion lab

[![ci](https://github.com/datascry/kitsune/actions/workflows/ci.yml/badge.svg)](https://github.com/datascry/kitsune/actions/workflows/ci.yml)
[![security](https://github.com/datascry/kitsune/actions/workflows/security.yml/badge.svg)](https://github.com/datascry/kitsune/actions/workflows/security.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![conventional commits](https://img.shields.io/badge/commits-conventional-fe5196.svg)](https://www.conventionalcommits.org)

<p align="center">
  <img src="docs/kitsune.jpg" alt="Kitsune — a nine-tailed fox spirit on a mountain ridge" width="320" />
</p>

Kitsune builds **both sides** of the bot-vs-human arms race in one repo — a fingerprint/behavioral
**detector** ("blue") and an anti-detect **evader fleet** ("red") — and runs them against each other,
producing a reproducible, per-layer scoreboard. Named after the shapeshifting fox spirit.

Its thesis: **flag _incoherence across layers_, not just bad signals.** A Chrome TLS handshake is
only suspicious when it arrives on the same session as a Linux TCP stack, a `webdriver`-tampered DOM,
and a datacenter ASN. So the architecture is a **session-correlation pipeline**, not just a detector.

Precision is a first-class concern. Scoring is a transparent noisy-or with cross-layer amplification,
behind a **conviction gate**: a `bot` verdict requires a *convicting* signal (coherence / automation /
artifact); environment, behavioral, reputation, and prevalence tells only ever *corroborate* — so a
stripped-but-real browser can't noisy-or its way to `bot`. Every rule is grounded against a real
browser before shipping, and the [calibration harness](docs/calibration.md) is the trusted-but-verified
false-positive gate.

```
 evader ─▶ EDGE (Go: TLS/HTTP2/TCP-IP fingerprint + session id) ─▶ APP (serves collector, ingests telemetry)
                       │                                   │
                       └──────────── Signals (session_id) ─┴─▶ DETECTOR (Python: coherence engine)
                                                                     │
                                                       STORE ─▶ HARNESS ─▶ per-layer SCOREBOARD
```

## Components

| Component | Lang | What it is | Tests |
|---|---|---|---|
| [`contracts/`](contracts) | JSON Schema | The stable core — the only coupling between components | validated in CI |
| [`detector/`](detector) | Python | Session correlation + data-driven coherence engine + a **conviction-gated** noisy-or scorer + prevalence/likelihood model + IP-reputation enrichment | **~100%** |
| [`harness/`](harness) | Python | Reproducible scoreboard + the **calibration** precision gate (trusted-but-verified, multi-source) + conviction-gated coordination/fleet scorer + biomech calibration (ethics enforced in code) | **~97%** |
| [`edge/`](edge) | Go | Multi-layer network fingerprinting + session minting: TLS ClientHello → JA3/JA4 (+ GREASE, post-quantum key-share), HTTP/2 preface (Akamai h2 + JA4H header order + unknown-engine), TCP/IP-stack OS (p0f-style SYN capture), **QUIC/HTTP-3 ClientHello (RFC 9001 Initial decrypt)**, and HTTP/2 DoS attribution (rapid-reset, CONTINUATION flood) | fingerprint **~97%** |
| [`collector/`](collector) | TypeScript | In-browser fingerprint + behavioral collection (mouse-direction entropy / straightness / velocity-CV / keystroke entropy) + a CreepJS-style live self-test page running the full probe suite, incl. the main-vs-Worker/iframe **realm-coherence** family | **100%** (logic) |
| [`evaders/`](evaders) | Py/TS/Go | Red-team fleet — every open-source family: scripted/TLS-mimicry (httpx, curl-impersonate, **primp**, **go-tls/uTLS**), Playwright-stealth, CDP-leak patches (patchright, rebrowser), CDP-native (nodriver, zendriver, pydoll), isolated-world Selenium (undetected, selenium-driverless), engine-level (Camoufox), farbling (Brave), and HTTP/2 DoS | all scored `bot` ([matrix](docs/matrix.md)) |

## Quickstart

```sh
# Python spine (detector + harness) — runs the scoreboard demo
cd harness && uv sync && uv run python -m kitsune_harness

# everything, locally
task ci            # headers · detector · harness · edge · collector
```

Example scoreboard (vanilla vs a naive bot, replayed through the live detector):

```
| Evader    | Ver   | Network | Browser | Behavioral | Reputation | Incoh. | Score | Label |
| vanilla   | 0.1.0 | 0.00    | 0.00    | 0.00       | 0.00       | 0.00   | 0.00  | human |
| naive-bot | 0.1.0 | 0.95    | 1.00    | 0.80       | 0.50       | 0.88   | 1.00  | bot   |
```

## Docs

- [Architecture](docs/architecture.md) — the design: the session-correlation pipeline, the coherence
  engine, the conviction-gated scorer, the structural frontiers, and the calibration discipline.
- [Findings](docs/findings.md) — the arms-race narrative: each evasion, the layer that caught it, and why
  (the engine-level Camoufox frontier, the precision turn, the realm-coherence family, the HTTP/2 DoS family, …).
- [Calibration](docs/calibration.md) — the trusted-but-verified false-positive gate (multi-source).
- [Prevalence model](docs/prevalence-model.md) · [Coordination](docs/coordination-proxy.md) — the two structural frontiers.
- [Detection catalog](docs/detection-catalog.md) · [Evasion catalog](docs/evasion-catalog.md) — the blue/red work queues.
- [Coverage matrix](docs/matrix.md) — detector rule × evader, with the detection-class breakdown.
- [Decision records](docs/adr) — MADR ADRs for the load-bearing decisions.
- [Catalog](docs/catalog.md) — relevant projects across the arms race.
- [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

## Ethics

Targets are **only** Kitsune's own detector and a fixed set of public test endpoints built for this
(sannysoft, CreepJS, BrowserLeaks, tls.peet.ws, fingerprint.com demo, incolumitas). Never a
third-party or production site. The allow-list is enforced in code. The self-contained arena _is_ the
ethics design.

## License

[MIT](LICENSE).
