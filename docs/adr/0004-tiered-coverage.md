# 0004. Tiered test-coverage gates

- Status: Accepted
- Date: 2026-06-17

## Context and Problem Statement

We want a high quality bar (the target was >95% coverage), but a flat 95% gate on inherently-IO code
(real browsers, raw sockets, LLM agents) forces heavy mocking that produces fragile tests which
verify the mocks, not the behaviour.

## Decision Drivers

- High confidence in the algorithmic core (scoring, coherence, fingerprint parsing, contracts).
- Honest, non-brittle tests for IO/integration boundaries.

## Considered Options

- **Flat ≥95% everywhere**, mocking browsers/sockets/LLMs aggressively.
- **Tiered gates**: ≥95% on core logic; integration/e2e tests + a lower gate on IO components.

## Decision Outcome

Chosen: **tiered gates.** Core logic (contracts, detector scoring + coherence, harness, edge
fingerprinting, collector pure logic) is gated at **≥95%** (currently 100%). Inherently-IO
components (edge proxy networking, collector browser glue, evaders) carry integration tests at a
lower gate, and silent caps are logged.

### Consequences

- Good: the parts that decide a verdict are exhaustively tested; IO tests stay meaningful.
- Bad / cost: coverage is not a single uniform number; reviewers must understand the tiers (recorded
  here and in `docs/architecture.md` §9).
