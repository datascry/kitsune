// collector/livepage/registry — types for the browser-consumable rule registry JSON.
// Mirrors harness/rules_json output: one entry per evaluable rule plus a clientEvaluable flag.

import type { Layer } from "../types.js";

export type PredicateName =
  | "present"
  | "absent"
  | "equals"
  | "not_equal"
  | "below_threshold"
  | "above_threshold";

export type RuleStatus = "active" | "experimental";

export interface RuleJSON {
  id: string;
  title: string;
  layers: Layer[];
  reads: string[];
  predicate: PredicateName;
  threshold: number | null;
  weight: number;
  category: string;
  status: RuleStatus;
  /** True iff every read is a browser/behavioral signal — resolvable without the edge. */
  clientEvaluable: boolean;
}

export interface RegistryJSON {
  ruleset_version: string;
  rules: RuleJSON[];
}
