# detector/ — the blue-team brain (Python)

Session-correlated, cross-layer **incoherence** scoring. Ingests `Signal` envelopes from the edge
(network) and collector (browser/behavioral), correlates them by `session_id` into a `Session`, runs
the data-driven coherence engine, and emits an explainable `Verdict`.

## Layout

| Module | Role |
|---|---|
| `models.py` | Pydantic models mirroring the contracts (`Signal`/`Session`/`Verdict`/…). |
| `contracts.py` | Locate + validate the JSON-Schema contracts; load the rule registry. |
| `coherence/` | `predicates.py` (the fixed predicate vocabulary), `rules.py` (rules-as-data), `engine.py` (generic evaluator). |
| `scoring.py` | Transparent noisy-or scoring; cross-layer contradictions amplified by `INCOHERENCE_WEIGHT`. |
| `reputation.py` | Offline datacenter-ASN classification (no paid API). |
| `ingest.py` | The correlation join: flat signals → `Session`s. |
| `store.py` | Schema-versioned SQLite persistence. |
| `detector.py` | The `Detector` facade. |
| `app.py` | FastAPI HTTP boundary (`/ingest`, `/verdict/{id}`, `/scoreboard`, `/healthz`). |

## Develop

```sh
uv sync                       # install (Python >=3.11)
uv run pytest                 # tests + coverage gate (>=95%, currently 100%)
uv run ruff check . && uv run ruff format --check .
uv run mypy                   # strict
uv run python -m kitsune_detector   # serve on :8080
```

Coverage is **tiered** (see `docs/architecture.md` §9): this package is core logic and is gated at
**≥95%**. The contracts in `../contracts/` are the test oracle — every example fixture must validate,
round-trip, and score.
