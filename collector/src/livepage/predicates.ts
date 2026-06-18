// collector/livepage/predicates — the fixed predicate vocabulary, ported from the Python detector.
// Pure functions deciding when a rule fires over resolved signal values; faithful to predicates.py.

import type { SignalValue } from "../types.js";
import type { PredicateName } from "./registry.js";

/** Sentinel for a signal the session never produced — distinct from a present null/false value. */
export const MISSING = Symbol("MISSING");
export type Resolved = SignalValue | typeof MISSING;

/** Resolved value at an index, treating an absent slot as MISSING (noUncheckedIndexedAccess-safe). */
function at(values: Resolved[], i: number): Resolved {
  const v = values[i];
  return v === undefined ? MISSING : v;
}

/** Truthy and not the MISSING sentinel (mirrors detector's _present). */
function isPresent(value: Resolved): boolean {
  return value !== MISSING && Boolean(value);
}

/** A real numeric reading — booleans are never numeric (mirrors detector's _is_number). */
function isNumber(value: Resolved): value is number {
  return typeof value === "number";
}

export type Predicate = (values: Resolved[], threshold: number | null) => boolean;

export const PREDICATES: Record<PredicateName, Predicate> = {
  present: (values) => isPresent(at(values, 0)),
  absent: (values) => !isPresent(at(values, 0)),
  equals: (values) => {
    const a = at(values, 0);
    const b = at(values, 1);
    return a !== MISSING && b !== MISSING && a === b;
  },
  not_equal: (values) => {
    // Only fire when BOTH sides are present — missing data is not a contradiction.
    const a = at(values, 0);
    const b = at(values, 1);
    return a !== MISSING && b !== MISSING && a !== b;
  },
  below_threshold: (values, threshold) => {
    const v = at(values, 0);
    return threshold !== null && isNumber(v) && v < threshold;
  },
  above_threshold: (values, threshold) => {
    const v = at(values, 0);
    return threshold !== null && isNumber(v) && v > threshold;
  },
};
