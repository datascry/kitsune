# evaders/agent — LLM-driven browser agent (claude -p as the brain)

Status: **live** ✅ — uses the Claude Code CLI (`claude -p`) as the reasoning engine; no API key
needed. The brain runs on the host; the browser runs in the Playwright container and is driven over
CDP. This is the headline experiment: *does a reasoning agent defeat the layers scripted bots trip?*

## Loop

```
host: claude -p  ──action JSON──▶  Chromium (in Playwright container, via CDP) ──▶ edge ──▶ detector
        ▲                                                                                      │
        └──────────── page snapshot ◀── browser ◀──────────────────────  verdict ◀────────────┘
```

Each step: snapshot the page → `claude -p "pick the next human action as JSON"` → execute (mouse /
type / scroll) → repeat. The reasoning step (`brain.py`) is pure and unit-tested (100%); the browser
driving (`runner.py`) is integration.

## Measured result (real claude-driven run, live stack)

| layer | score | |
|---|---|---|
| network | 0.0 | TLS clean |
| browser | 0.0 | webdriver + headless tells patched — **beats the fingerprint layers** |
| **behavioral** | **0.8** | **caught**: `bh.input_entropy_floor`, `bh.no_input_before_action` |
| **verdict** | **bot (0.80)** | |

**This is the thesis.** The agent defeats the network and browser/fingerprint layers but is caught by
the **behavioral** layer — its actions didn't produce human-like pointer entropy. Confirms the catalog
finding (catalog §8): base agents don't beat behavioral detection on their own; the durable signal is
behavioral / intent / coordination. Beating it needs human-input synthesis (ghost-cursor-style) — the
phase-4 frontier.

## Run

```sh
docker compose -f docker-compose.yml -f docker-compose.agent.yml up -d --build detector edge browser
cd evaders/agent && uv sync
KITSUNE_BROWSER_WS=http://localhost:9222 KITSUNE_DETECTOR=http://localhost:8090 \
  uv run python -m kitsune_agent          # spends Claude usage: KITSUNE_AGENT_STEPS calls
```

> Cost note: every step calls `claude -p`, consuming Claude usage. `KITSUNE_AGENT_STEPS` (default 2)
> bounds it.
