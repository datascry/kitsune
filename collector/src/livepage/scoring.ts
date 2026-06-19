// collector/livepage/scoring — noisy-or verdict scoring, ported from the Python detector.
// Cross-layer (incoherence) contradictions are amplified; faithful to scoring.py + config.py.

import type { Layer } from "../types.js";
import type { Contradiction } from "./engine.js";

// Mirror detector/config.py.
export const SUSPICIOUS_THRESHOLD = 0.35;
export const BOT_THRESHOLD = 0.65;
export const INCOHERENCE_WEIGHT = 0.5;

export type Label = "human" | "suspicious" | "bot";

// Mirror detector/scoring.py CONVICTING_CATEGORIES. A `bot` conviction requires a *convicting* tell — a
// clear bot signature (cross-vector coherence contradiction, automation artifact, or injected-code
// artifact). Environment / behavioral / reputation / prevalence tells only CORROBORATE: they raise the
// score up to `suspicious` but can never noisy-or their way to `bot` on their own. Without this gate a real
// browser that trips a few benign environment tells (no webcam, stripped plugins) is mislabelled `bot`.
const CONVICTING_CATEGORIES = new Set(["coherence", "automation", "artifact"]);

/** True if any fired contradiction is a convicting (coherence/automation/artifact) signature. */
export function hasConvicting(contradictions: Contradiction[]): boolean {
  return contradictions.some((c) => CONVICTING_CATEGORIES.has(c.category));
}

export interface LayerScores {
  network: number;
  browser: number;
  behavioral: number;
  reputation: number;
}

/** Combine independent probabilities: 1 - ∏(1 - w). Empty -> 0.0. */
export function noisyOr(weights: number[]): number {
  return 1 - weights.reduce((p, w) => p * (1 - w), 1);
}

function isCrossLayer(layers: Layer[]): boolean {
  return new Set(layers).size >= 2;
}

/** Cross-layer contradictions count for more — incoherence is the differentiator. */
function effectiveWeight(c: Contradiction): number {
  if (isCrossLayer(c.layers)) {
    return Math.min(1, c.weight * (1 + INCOHERENCE_WEIGHT));
  }
  return c.weight;
}

/** Per-layer score = noisy-or of the weights of contradictions touching that layer. */
export function layerScores(contradictions: Contradiction[]): LayerScores {
  const buckets: Record<keyof LayerScores, number[]> = {
    network: [],
    browser: [],
    behavioral: [],
    reputation: [],
  };
  for (const c of contradictions) {
    for (const layer of new Set(c.layers)) {
      buckets[layer].push(c.weight);
    }
  }
  return {
    network: noisyOr(buckets.network),
    browser: noisyOr(buckets.browser),
    behavioral: noisyOr(buckets.behavioral),
    reputation: noisyOr(buckets.reputation),
  };
}

/** Noisy-or over only the cross-layer contradictions — the thesis metric. */
export function incoherenceScore(contradictions: Contradiction[]): number {
  return noisyOr(contradictions.filter((c) => isCrossLayer(c.layers)).map((c) => c.weight));
}

/** Noisy-or over every contradiction's effective (incoherence-amplified) weight. */
export function finalScore(contradictions: Contradiction[]): number {
  return noisyOr(contradictions.map(effectiveWeight));
}

/** Map a score to a label, gating `bot` on a convicting signal (mirrors detector/scoring.py label_for).
 * A `bot` conviction needs both a bot-level score AND a convicting contradiction; corroborating-only tells
 * cap at `suspicious`. Omitting `contradictions` skips the gate (bare threshold lookup). */
export function labelFor(score: number, contradictions?: Contradiction[]): Label {
  if (score >= BOT_THRESHOLD && (contradictions === undefined || hasConvicting(contradictions))) {
    return "bot";
  }
  if (score >= SUSPICIOUS_THRESHOLD) return "suspicious";
  return "human";
}
