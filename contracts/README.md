# contracts/ — the stable core

Language-agnostic [JSON Schema (draft 2020-12)](https://json-schema.org/) definitions plus the
coherence-rule registry that every Kitsune component speaks. **This is the only coupling between
components** — the polyglot detector (Python), edge (Go), collector (TypeScript) and harness
(Python) never import each other; they exchange these envelopes over HTTP and validate against these
schemas.

| File | Entity |
|---|---|
| `signal.schema.json` | One observation from one layer at one moment, tagged with the correlating `session_id`. |
| `session.schema.json` | All signals sharing a `session_id`, grouped by layer — the unit coherence runs over. |
| `verdict.schema.json` | The scored result: per-layer scores, the contradictions that fired (each with evidence), and the final `score`/`label`. |
| `coherence-rule.schema.json` | The shape of one coherence rule (rules are data, not code). |
| `rules/registry.yaml` | The live coherence-rule registry. |
| `examples/` | Golden fixtures (`session_bot.json`, `session_human.json`); validated against the schemas in CI and reused as detector test oracles. |

## The four layers

Every signal, session bucket, layer score and rule is keyed on one of four layers:
**`network`** (TLS/JA4, HTTP/2, QUIC, TCP/IP), **`browser`** (fingerprint + JS environment),
**`behavioral`** (mouse/keystroke dynamics), **`reputation`** (IP/ASN). Kitsune's thesis is to flag
*incoherence across these layers*, not just a single bad signal.

## Rules as data

The detector's coherence engine is a small generic evaluator; the detection knowledge lives in
`rules/registry.yaml` (see [ADR-0003](../docs/adr/0003-rules-as-data-coherence.md)). The registry is
the single source of truth for what Kitsune detects. Each rule (`coherence-rule.schema.json`)
carries:

- `id` — namespaced, e.g. `net.tls_os_vs_tcp_os` · `title` · `weight` (0–1, contribution to score).
- `layers` — which of the four layers it spans · `reads` — the `layer.kind` signal references its
  predicate consumes, in order.
- `predicate` — one of `present` / `absent` / `equals` / `not_equal` / `not_equal_browser` /
  `below_threshold` / `above_threshold` (the threshold pair requires a `threshold`; the
  `equals`/`not_equal`/`not_equal_browser` family requires two `reads`). `not_equal_browser` is a
  family-aware `not_equal`: it collapses the Chromium family (edge/brave/opera/vivaldi/samsung →
  chrome) before comparing, so a same-engine UA doesn't fire — used by the JA4↔UA and h2↔UA browser
  tells. A rule *fires* — emitting a `Contradiction` with the triggering evidence — when its
  predicate holds.
- `category` — the kind of tell: `coherence` (cross-layer contradiction), `environment`,
  `automation`, `artifact`, `behavioral`, `reputation`, `prevalence`.
- `status` — `active` (convicts), `experimental` (corroborating / awaiting validation) or `retired`
  (a decayed signal, kept for history — never deleted).
- `source`, `added`, `last_validated` — provenance and a "signal decay" audit trail.

Retiring a signal that a browser change has killed is a one-line `status` edit, not a code change.

## Versioning

Two independent versions:

- **`schema_version`** (`MAJOR.MINOR`) on every wire envelope — currently **0.1**. Adding an optional
  field is a MINOR bump; changing/removing a field or tightening validation is a MAJOR bump and
  requires a migration note. See [ADR-0002](../docs/adr/0002-polyglot-with-contracts.md).
- **`ruleset_version`** at the head of `registry.yaml` (the live value lives there — don't duplicate
  it here) and echoed into each verdict, so a scoreboard pins exactly which ruleset produced it.

## Validation

```sh
task contracts:validate     # validates every schema + every examples/*.json + the rule registry
```

CI fails if any schema is malformed or any example/fixture stops validating — that makes the
contracts a tripwire: you cannot land a change that silently breaks the wire format.
