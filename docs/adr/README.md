# Architecture Decision Records

Significant design decisions are captured here as [MADR](https://adr.github.io/madr/) records —
short, immutable documents stating the context, the options weighed, and the decision. They explain
*why* the code is the way it is.

- New decision → copy `0000-adr-template.md`, number it next in sequence, set status `Accepted`.
- Superseding a decision → add a new ADR and mark the old one `Superseded by ADR-XXXX` (don't delete).

| ADR | Title | Status |
|---|---|---|
| [0001](0001-session-correlation-pipeline.md) | Session-correlation pipeline as the architectural keystone | Accepted |
| [0002](0002-polyglot-with-contracts.md) | Polyglot components coupled only by versioned contracts | Accepted |
| [0003](0003-rules-as-data-coherence.md) | Coherence rules as data, not code | Accepted |
| [0004](0004-tiered-coverage.md) | Tiered test-coverage gates | Accepted |
