# 0003. Coherence rules as data, not code

- Status: Accepted
- Date: 2026-06-17

## Context and Problem Statement

Bot-detection signals decay fast — e.g. a 2024 V8 change silently killed the classic `Error.stack`
CDP tell. The set of cross-layer incoherence checks will churn constantly. How do we encode this
knowledge so it can evolve without destabilising the detector?

## Decision Drivers

- Signals are added/retired frequently; the detector core should not churn with them.
- We want to chart signal decay over time (provenance) for the writeup and for honesty.
- Rules should be reviewable by non-Python readers.

## Considered Options

- **Hard-coded rules** as Python functions in the detector.
- **Rules as data** (a YAML registry) evaluated by a small generic engine over a fixed predicate
  vocabulary.

## Decision Outcome

Chosen: **rules as data.** `contracts/rules/registry.yaml` declares each rule (layers, the signals
it reads, a predicate, a weight, and provenance: `added`/`last_validated`/`status`). The engine is a
generic evaluator; predicates are a small, tested set. Retiring a decayed signal is a one-line
status change, not a refactor.

### Consequences

- Good: knowledge evolves independently of the engine; provenance enables a "signal decay" view;
  rules are diff-friendly and language-agnostic.
- Bad / cost: genuinely new comparison shapes still need a new predicate in code; expressing complex
  composite conditions in data is more constrained than arbitrary code (accepted for now).
