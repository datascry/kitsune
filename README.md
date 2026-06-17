# 🦊 Kitsune — a bot detection ⇄ evasion lab

[![ci](https://github.com/kitsune-lab/kitsune/actions/workflows/ci.yml/badge.svg)](https://github.com/kitsune-lab/kitsune/actions/workflows/ci.yml)
[![security](https://github.com/kitsune-lab/kitsune/actions/workflows/security.yml/badge.svg)](https://github.com/kitsune-lab/kitsune/actions/workflows/security.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![conventional commits](https://img.shields.io/badge/commits-conventional-fe5196.svg)](https://www.conventionalcommits.org)

Kitsune builds **both sides** of the bot-vs-human arms race in one repo — a fingerprint/behavioral
**detector** ("blue") and an anti-detect **evader fleet** ("red") — and runs them against each other,
producing a reproducible, per-layer scoreboard. Named after the shapeshifting fox spirit.

Its thesis: **flag _incoherence across layers_, not just bad signals.** A Chrome TLS handshake is
only suspicious when it arrives on the same session as a Linux TCP stack, a `webdriver`-tampered DOM,
and a datacenter ASN. So the architecture is a **session-correlation pipeline**, not just a detector.

```
 evader ─▶ EDGE (Go: JA3/JA4 + session id) ─▶ APP (serves collector, ingests telemetry)
                       │                                   │
                       └──────────── Signals (session_id) ─┴─▶ DETECTOR (Python: coherence engine)
                                                                     │
                                                       STORE ─▶ HARNESS ─▶ per-layer SCOREBOARD
```

## Components

| Component | Lang | What it is | Tests |
|---|---|---|---|
| [`contracts/`](contracts) | JSON Schema | The stable core — the only coupling between components | validated in CI |
| [`detector/`](detector) | Python | Session correlation + data-driven coherence engine + scoring | **100%** |
| [`harness/`](harness) | Python | Scenario runner + reproducible scoreboard (ethics enforced) | **100%** |
| [`edge/`](edge) | Go | Raw ClientHello → JA3/JA4, session minting, signal forwarding | fingerprint **97%** |
| [`collector/`](collector) | TypeScript | In-browser fingerprint + behavioral collection | **100%** (logic) |
| [`evaders/`](evaders) | Py/TS/Go | Red-team ladder: vanilla → stealth → agent → go-tls | _stubs (phase 3)_ |

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
