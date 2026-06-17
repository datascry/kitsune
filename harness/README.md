# harness/ — orchestration + scoreboard (Python)

Runs evaders against the detector and emits a **dated, reproducible** per-layer scoreboard. Ethics
are enforced in code (`allowlist.py`), not just docs.

## Layout

| Module | Role |
|---|---|
| `allowlist.py` | The ethics invariant: evaders may only hit the local detector or the approved public test endpoints. |
| `scenarios.py` | `Scenario` protocol + `ReplayScenario` (replays a recorded session fixture — deterministic, no browser). |
| `harness.py` | `Harness.run(scenarios)` → scores each via the detector. |
| `scoreboard.py` | Render a `Scoreboard` to Markdown / JSON, with the evidence behind each verdict. |

## Run the spine demo

```sh
uv sync
uv run python -m kitsune_harness          # markdown scoreboard
uv run python -m kitsune_harness --json   # json
uv run pytest                             # tests + coverage gate (currently 100%)
```

Example output (vanilla vs a naive bot, replayed through the live detector):

```
| Evader    | Ver   | Network | Browser | Behavioral | Reputation | Incoh. | Score | Label |
| vanilla   | 0.1.0 | 0.00    | 0.00    | 0.00       | 0.00       | 0.00   | 0.00  | human |
| naive-bot | 0.1.0 | 0.95    | 1.00    | 0.80       | 0.50       | 0.88   | 1.00  | bot   |
```

Real evaders (stealth/agent/go-tls) implement the same `Scenario.collect()` surface by driving a
client through the edge; the harness scores them identically.
