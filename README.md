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
| [`detector/`](detector) | Python | Session correlation + data-driven coherence engine + IP-reputation enrichment + scoring | **100%** |
| [`harness/`](harness) | Python | Scenario runner + reproducible scoreboard + fleet/coordination scorer + biomechanics calibration (ethics enforced) | **100%** |
| [`edge/`](edge) | Go | Multi-layer network fingerprinting + session minting: TLS ClientHello → JA3/JA4 (+ GREASE, post-quantum key-share), HTTP/2 preface (Akamai h2 + unknown-engine), TCP/IP-stack OS (p0f-style SYN capture), **QUIC/HTTP-3 ClientHello (RFC 9001 Initial decrypt)**, and HTTP/2 DoS attribution (rapid-reset, CONTINUATION flood) | fingerprint **97%** |
| [`collector/`](collector) | TypeScript | In-browser fingerprint + behavioral collection (incl. movement biomechanics: 2/3 power law, sub-movements, fp-hash) | **100%** (logic) |
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

- [Architecture](docs/architecture.md) — the design, contracts, coherence engine, phasing, risks.
- [Findings](docs/findings.md) — the arms-race narrative: each evasion, the layer that caught it, and why
  (the engine-level Camoufox frontier, the environment-floor red-team, the HTTP/2 DoS family, …).
- [Coverage matrix](docs/matrix.md) — detector rule × evader, with the detection-class breakdown.
- [Decision records](docs/adr) — MADR ADRs for the load-bearing decisions.
- [Catalog](docs/catalog.md) — ~70 relevant projects across the arms race, with M0 picks.
- [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

## Ethics

Targets are **only** Kitsune's own detector and a fixed set of public test endpoints built for this
(sannysoft, CreepJS, BrowserLeaks, tls.peet.ws, fingerprint.com demo, incolumitas). Never a
third-party or production site. The allow-list is enforced in code. The self-contained arena _is_ the
ethics design.

## License

[MIT](LICENSE).
