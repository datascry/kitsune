# evaders/ — the red-team ladder

Each evader implements the harness `Scenario` surface (produce a session's signals by driving a
client through the edge) so the detector scores them all identically. They form a difficulty ladder
that maps directly onto the cross-layer incoherence thesis:

| Evader | Lang | Status | Defeats | Seeds from (catalog) |
|---|---|---|---|---|
| `vanilla` | Python | **live** ✅ | nothing (the control / detection floor) | httpx |
| `go-tls` | Go | **built** ✅ | the **network** (JA3/JA4) layer | uTLS, tls-client |
| `stealth` | Playwright (Node) | **live** ✅ | browser-FP + CDP layers | Playwright (→ Camoufox, patchright) |
| `agent` | Python | design stub | the **behavioral** layer (headline experiment) | browser-use, Claude Computer Use |

`vanilla` runs end-to-end (scores `human`, the floor); `go-tls` forges real Chrome/Firefox TLS
(tested); `stealth` drives a real Chromium through the live stack — naive automation scores `bot`
(0.985), the stealth variant scores `human`. `agent` is a design-complete stub (needs an LLM
runtime — see its README) and is phase-3 work.

> **Spine-first:** these are stubs. They are built out in phase 3 (`docs/architecture.md` §8). The
> detector, edge, collector, and harness are complete and the scoreboard already runs on replayed
> sessions.

## Ethics

Every evader may target **only** Kitsune's own detector and the approved public test endpoints — the
harness allow-list (`harness/src/kitsune_harness/allowlist.py`) refuses anything else. See
`SECURITY.md`.
