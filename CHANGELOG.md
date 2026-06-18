# Changelog

All notable changes to Kitsune are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Releases are cut automatically from
[Conventional Commits](https://www.conventionalcommits.org/) via release-please.

## [Unreleased]

### Added

- **Architecture & contracts.** Session-correlation design (`docs/architecture.md`) and the
  language-agnostic JSON-Schema contracts (`Signal`/`Session`/`Verdict`/`CoherenceRule`) plus the
  initial 10-rule coherence registry.
- **detector** (Python) — session correlation, the data-driven coherence engine, transparent
  noisy-or scoring with cross-layer amplification, SQLite store, and a FastAPI `/ingest` boundary.
  100% test coverage.
- **harness** (Python) — scenario runner + reproducible per-layer scoreboard (Markdown/JSON) with
  the ethics allow-list enforced in code. 100% test coverage.
- **edge** (Go) — raw ClientHello parser → JA3/JA4, session correlation, and signal forwarding.
- **collector** (TypeScript) — in-browser fingerprint + behavioral signal collection over an
  abstracted `BrowserEnv`. 100% test coverage of the pure logic.
- **Repo standards** — 2-line machine-scannable file headers (enforced), MADR ADRs, security
  posture (SECURITY.md, gitleaks, pinned actions, SBOM), supply-chain (Dependabot, license gate),
  community templates, and conventional-commit linting.
- **Live pipeline** — transparent TLS peek-proxy in the edge (captures the raw ClientHello, mints
  `ks_sid`, forwards JA3/JA4 signals), a real `vanilla` evader, and `docker-compose` wiring
  detector + edge + vanilla. Verified end-to-end (`session_id` threads socket → verdict).
- **`go-tls` evader** — uTLS-based Chrome/Firefox TLS fingerprint forging.
- **JA4 live network scoring** — detector `GET /session/{id}` to inspect captured signals; the edge's
  JA4 hint DB seeded with **real captured fingerprints** (go-tls Chrome, httpx), so the network layer
  recognises clients live (`ja4_browser_hint`/`ja4_os_hint` populate). (Browser-session network
  capture through the peek-proxy is a known follow-up — see `edge/README.md`.)
- **`stealth` evader (live)** — drives a real Chromium through the edge via Playwright (in the
  Playwright Docker image); the detector serves an in-page collector. Verified red-vs-blue result:
  naive automation scores `bot` (0.985, webdriver + headless tells), the stealth variant scores
  `human`.
- **`agent` evader (live)** — LLM-driven browser agent using `claude -p` as the reasoning engine
  (brain on host, Chromium in the Playwright container over CDP). Verified result: the agent beats
  the network + browser/fingerprint layers but is caught by the **behavioral** layer
  (`bot`, 0.80) — the thesis, demonstrated.
- **Coherence registry v0.2.0 → v0.3.0** — added HTTP/2-vs-TLS, headless-UA, keystroke-entropy, and
  proxy/Tor-exit rules (v0.2.0); then **deeper behavioral shape features** — mouse-path straightness
  and velocity coefficient-of-variation (collector + live demo page) with `bh.path_too_straight` and
  `bh.uniform_velocity` rules (v0.3.0), the start of the real behavioral frontier.
- **Unified live scoreboard** — `harness.live`/`liveboard` fold every evader's live verdict into one
  dated board; `scripts/live_scoreboard.sh` runs the whole fleet against the running stack and writes
  `docs/scoreboard.md` (vanilla → stealth → agent in one table).
- **docs/catalog.md** — opinionated catalog of ~70 relevant projects across the arms race.

[Unreleased]: https://github.com/datascry/kitsune/commits/main
