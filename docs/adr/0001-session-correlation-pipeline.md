# 0001. Session-correlation pipeline as the architectural keystone

- Status: Accepted
- Date: 2026-06-17

## Context and Problem Statement

Bot signals live at different layers — TLS/JA4 at the socket, HTTP/2 at the connection, fingerprint
and behaviour inside the page, reputation across requests. Kitsune's thesis is to flag *incoherence
across layers*. Incoherence can only be computed if signals from all layers are joined to one
interaction. How should the system be organised so that this join is reliable?

## Decision Drivers

- The thesis is unimplementable without cross-layer correlation.
- Layers are captured by different components in different languages.
- We want each layer independently developable and testable.

## Considered Options

- **A monolithic detector** that does capture and scoring in one process.
- **A session-correlated event pipeline**: every layer emits `Signal`s tagged with a `session_id`;
  a detector joins them into a `Session` and scores coherence.

## Decision Outcome

Chosen: the **session-correlated event pipeline**. The edge (first hop) mints the `session_id`, sets
it as a cookie and stamps it on forwarded requests; the collector tags its telemetry with it; the
detector joins by `session_id`. Correlation is the keystone built and tested first.

### Consequences

- Good: the thesis becomes implementable; layers compose; the join is the one thing an e2e test must
  prove before any layer is deepened.
- Good: components stay decoupled (no shared memory/code, only the `session_id` + contracts).
- Bad / cost: requires threading an id across process and language boundaries and a correlation
  store; a wrong join silently breaks scoring, so it needs explicit end-to-end testing.
