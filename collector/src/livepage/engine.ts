// collector/livepage/engine — evaluate the rule registry against collected signals, in the browser.
// Mirrors detector/coherence/engine.py: resolve each rule's reads, fire its predicate, score a verdict.

import type { Layer, SignalValue } from "../types.js";
import { MISSING, PREDICATES, type Resolved } from "./predicates.js";
import type { RuleJSON } from "./registry.js";
import {
  finalScore,
  incoherenceScore,
  type Label,
  labelFor,
  layerScores,
  type LayerScores,
} from "./scoring.js";

/** A signal map keyed by "layer.kind" — the same reference form rules read. */
export type SignalMap = Map<string, SignalValue>;

export interface Contradiction {
  id: string;
  title: string;
  layers: Layer[];
  weight: number;
  category: string;
  /** The "layer.kind" references whose values fired the rule. */
  evidence: string[];
}

function resolve(signals: SignalMap, ref: string): Resolved {
  return signals.has(ref) ? (signals.get(ref) as SignalValue) : MISSING;
}

/** Fire every rule whose predicate holds over its resolved reads — returns the contradictions. */
export function evaluate(rules: RuleJSON[], signals: SignalMap): Contradiction[] {
  const out: Contradiction[] = [];
  for (const rule of rules) {
    const values = rule.reads.map((ref) => resolve(signals, ref));
    if (PREDICATES[rule.predicate](values, rule.threshold)) {
      out.push({
        id: rule.id,
        title: rule.title,
        layers: rule.layers,
        weight: rule.weight,
        category: rule.category,
        evidence: rule.reads,
      });
    }
  }
  return out;
}

export interface Verdict {
  score: number;
  label: Label;
  incoherence: number;
  layers: LayerScores;
  contradictions: Contradiction[];
}

export function verdictFor(contradictions: Contradiction[]): Verdict {
  const score = finalScore(contradictions);
  return {
    score,
    label: labelFor(score, contradictions), // conviction-gated: corroborating-only tells cap at suspicious
    incoherence: incoherenceScore(contradictions),
    layers: layerScores(contradictions),
    contradictions,
  };
}
