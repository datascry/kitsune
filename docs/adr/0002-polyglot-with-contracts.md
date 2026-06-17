# 0002. Polyglot components coupled only by versioned contracts

- Status: Accepted
- Date: 2026-06-17

## Context and Problem Statement

Each layer has a natural ecosystem: TLS fingerprinting is a Go world, ML/behavioral scoring is a
Python world, in-browser collection must be TypeScript. Forcing one language puts some layer in the
wrong toolchain. But multiple languages risk a tangle of cross-language coupling.

## Decision Drivers

- Use the best ecosystem per layer (also serves the author's Go-learning goal).
- Keep components independently swappable and testable.
- Avoid a build where a change in one language breaks another.

## Considered Options

- **Single language** (e.g. all Node or all Python) for simplicity.
- **Polyglot, coupled by shared libraries** across languages.
- **Polyglot, coupled only by versioned JSON-Schema contracts over HTTP.**

## Decision Outcome

Chosen: **polyglot, coupled only by the `contracts/` JSON Schemas.** Go (edge), Python
(detector/harness), TypeScript (collector) communicate over HTTP with contract-valid envelopes and
never import each other. Schemas carry a `schema_version`; adding a field is a minor bump,
changing/removing one is a major bump + migration.

### Consequences

- Good: each layer uses the right tools; the contracts are the single, testable coupling; any
  component can be rewritten behind the same schema.
- Bad / cost: three toolchains and a multi-job CI; the contracts must be governed carefully because
  they are the load-bearing interface.
