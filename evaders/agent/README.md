# evaders/agent — LLM-driven browser agent (the headline experiment)

Status: **design stub.** Needs an LLM runtime (an API key / a Computer-Use loop), so it is not wired
or tested in CI yet. The experiment it runs is the point of the whole lab.

## The experiment

Scripted bots trip the **behavioral** layer (no human-like input entropy). The hypothesis: a
reasoning agent that perceives and acts at the OS level produces human-like cursor trajectories and
timing, defeating the behavioral layer — proving the durable signal moves to **intent / coordination
/ cross-layer coherence**, not per-event mechanics.

## Two arms to compare (from `docs/catalog.md` §8)

- **DOM/CDP-driven** (`browser-use`, Playwright-MCP, Skyvern) — drives via CDP + structured DOM
  actions → *should still trip* the behavioral + CDP layers. The "naive agent" control.
- **Vision / Computer-Use** (Claude Computer Use, OpenAI CUA) — perceives screenshots, emits OS-level
  mouse/keyboard → *may defeat* the behavioral layer. The headline arm.

Both drive a browser through the edge and are scored identically via the harness `Scenario` surface;
the interesting result is the **behavioral-layer delta** between the two arms.

## Ethics

The agent is bound by the same allow-list as every evader
(`harness/src/kitsune_harness/allowlist.py`): it may only act against the local detector and the
approved public test endpoints. Never a third-party or production site.
