# evaders/ — the red-team ladder

Each evader implements the harness `Scenario` surface (produce a session's signals by driving a
client through the edge) so the detector scores them all identically. They form a difficulty ladder
that maps directly onto the cross-layer incoherence thesis:

| Evader | Lang | Status | Defeats | Seeds from (catalog) |
|---|---|---|---|---|
| `vanilla` | Python | **live** ✅ | nothing (the control / detection floor) | httpx |
| `go-tls` | Go | **built** ✅ | the **network** (JA3/JA4) layer | uTLS, tls-client |
| `stealth` | Playwright (Node) | **live** ✅ | browser-FP + CDP layers | Playwright (→ Camoufox, patchright) |
| `agent` | Python + `claude -p` | **live** ✅ | the **behavioral** layer (headline experiment) | Claude Code CLI, Playwright/CDP |

All four run for real. The live scoreboard tells the whole arms-race story:

| evader | label | caught on |
|---|---|---|
| `vanilla` | 🧑 human (0.00) | nothing — the floor |
| `stealth` naive | 🤖 bot (0.985) | browser: `webdriver` + headless UA |
| `stealth` patched | 🧑 human (0.00) | nothing — beats the fingerprint layers |
| `agent` (claude -p) | 🤖 bot (0.80) | **behavioral**: low pointer entropy |

The headline result: the agent beats the network + browser layers but the **behavioral** layer catches
it — the durable signal is behavioral / intent, exactly the thesis. `go-tls` forges real Chrome/Firefox
TLS (tested). Beating the behavioral layer (human-input synthesis) is the phase-4 frontier.

> **Spine-first:** these are stubs. They are built out in phase 3 (`docs/architecture.md` §8). The
> detector, edge, collector, and harness are complete and the scoreboard already runs on replayed
> sessions.

## Ethics

Every evader may target **only** Kitsune's own detector and the approved public test endpoints — the
harness allow-list (`harness/src/kitsune_harness/allowlist.py`) refuses anything else. See
`SECURITY.md`.
