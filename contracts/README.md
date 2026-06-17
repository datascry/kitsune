# contracts/ — the stable core

Language-agnostic [JSON Schema (draft 2020-12)](https://json-schema.org/) definitions that every
Kitsune component speaks. **This is the only coupling between components** — nothing imports anything
across the polyglot boundary; they exchange these envelopes over HTTP.

| File | Entity |
|---|---|
| `signal.schema.json` | One observation from one layer (`session_id`-tagged). |
| `session.schema.json` | All signals sharing a `session_id`, grouped by layer. |
| `verdict.schema.json` | The scored result; contradictions carry evidence. |
| `coherence-rule.schema.json` | The shape of a coherence rule (rules are data). |
| `rules/registry.yaml` | The live coherence-rule registry. |
| `examples/` | Golden fixtures; validated against the schemas in CI and reused as detector test oracles. |

## Versioning

Every envelope carries `schema_version` (`MAJOR.MINOR`). Adding an optional field is a MINOR bump;
changing or removing a field, or tightening validation, is a MAJOR bump and requires a migration note.
Current: **0.1**.

## Validation

```sh
task contracts:validate     # validates every schema + every examples/*.json + the rule registry
```

CI fails if any schema is malformed or any example/fixture stops validating — that makes the contracts
a tripwire: you cannot land a change that silently breaks the wire format.
