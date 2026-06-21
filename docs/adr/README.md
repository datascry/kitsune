# Architecture Decision Records

Significant design decisions are captured here as [MADR](https://adr.github.io/madr/) records —
short, immutable documents stating the context, the options weighed, and the decision made. They
explain *why* the code is the way it is. For the system overview those decisions add up to, start
with [`docs/architecture.md`](../architecture.md).

| ADR | Title | Status |
|---|---|---|
| [0001](0001-session-correlation-pipeline.md) | Session-correlation pipeline as the architectural keystone | Accepted |
| [0002](0002-polyglot-with-contracts.md) | Polyglot components coupled only by versioned contracts | Accepted |
| [0003](0003-rules-as-data-coherence.md) | Coherence rules as data, not code | Accepted |
| [0004](0004-tiered-coverage.md) | Tiered test-coverage gates | Accepted |
| [0005](0005-per-connection-quic-attribution.md) | Per-connection QUIC/HTTP-3 attribution for within-session coherence | Proposed |

- **0001** — Bot signals live at different layers; incoherence can only be computed if they are
  joined to one interaction. Every layer emits `Signal`s tagged with a `session_id` (minted by the
  edge); the detector joins them into a `Session` and scores coherence. Correlation is the keystone,
  built and tested first.
- **0002** — Each layer wants its own ecosystem (Go for TLS, Python for scoring, TS in-browser).
  Components are polyglot and coupled *only* by the versioned `contracts/` JSON Schemas over HTTP —
  they never import each other, so any one can be rewritten behind the same schema.
- **0003** — Detection signals decay fast, so the checks churn constantly. Rules live as data in
  `contracts/rules/registry.yaml`, evaluated by a small generic engine over a fixed predicate
  vocabulary; retiring a decayed signal is a one-line `status` change, not a refactor.
- **0004** — A flat ≥95% coverage gate forces brittle mocking of inherently-IO code. Tiered gates
  instead: ≥95% on the algorithmic core (contracts, scoring, coherence, fingerprint parsing),
  integration/e2e tests at a lower gate on IO components (proxy, browser glue, evaders).
- **0005** (Proposed) — QUIC is the last gap in the within-session coherence axis. The edge attributes
  QUIC fingerprints *per source IP* (elicit-and-close capture), which is NAT-confounded, single-shot,
  and ungroundable — so the QUIC rules were retired and a rotation rule can't ship. Decision: serve H3
  and key the captured Initial by *connection ID* (`ks_sid`-attributed, migration-safe). Plumbing is
  buildable/unit-testable in-sandbox; rule promotion stays gated on out-of-sandbox GROUNDED-LIVE
  evidence (a browser-trusted cert + a QUIC rotation evader).

## Writing a new ADR

- New decision → copy [`0000-adr-template.md`](0000-adr-template.md), number it next in sequence, set
  status `Accepted`, and add a row + a one-line summary above.
- Superseding a decision → add a new ADR and mark the old one `Superseded by ADR-XXXX` (don't delete;
  the history is the point).
