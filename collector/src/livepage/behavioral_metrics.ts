// collector/livepage/behavioral_metrics — pure scoring for the live behavioural panel.
// Scores each measured biomech metric against its REAL registry bot-floor; no DOM, fully unit-tested.

import { mouseEntropy, pathStraightness, velocityCV } from "../behavioral.js";
import type { PointerSample } from "../types.js";
import { PREDICATES } from "./predicates.js";
import type { BehavioralSnapshot } from "./probes.js";
import type { PredicateName, RuleJSON } from "./registry.js";

/** A behavioural rule with its measured value and live verdict — the per-metric row the panel renders. */
export interface BehavioralRow {
  ruleId: string;
  label: string;
  value: number;
  /** Whether enough genuine input has been captured to judge this metric yet. */
  ready: boolean;
  threshold: number | null;
  predicate: PredicateName;
  /** The rule's predicate held over the measured value — i.e. this metric looks bot-like. */
  fires: boolean;
  /** Human-readable floor, e.g. "< 0.15" or "> 0.97". */
  floorText: string;
}

interface MetricSpec {
  ruleId: string;
  label: string;
  value: (s: BehavioralSnapshot) => number;
  ready: (s: BehavioralSnapshot) => boolean;
}

// Each panel metric maps to the registry rule whose threshold IS its bot-floor — read from the fetched
// rules.json so the displayed floor can never drift from the detector's actual ruleset.
const METRICS: MetricSpec[] = [
  {
    ruleId: "bh.input_entropy_floor",
    label: "Movement-direction entropy",
    value: (s) => s.mouseEntropy,
    ready: (s) => s.enoughMotion,
  },
  {
    ruleId: "bh.path_too_straight",
    label: "Path straightness",
    value: (s) => s.mouseStraightness,
    ready: (s) => s.enoughMotion,
  },
  {
    ruleId: "bh.uniform_velocity",
    label: "Velocity variation (CV)",
    value: (s) => s.mouseVelocityCv,
    ready: (s) => s.enoughMotion,
  },
  {
    ruleId: "bh.keystroke_entropy_floor",
    label: "Keystroke-timing entropy",
    value: (s) => s.keystrokeEntropy,
    ready: (s) => s.enoughKeys,
  },
  {
    ruleId: "bh.touch_uniform_velocity",
    label: "Swipe velocity variation (CV)",
    value: (s) => s.touchVelocityCv,
    ready: (s) => s.touchVelocityCv >= 0,
  },
];

function floorText(predicate: PredicateName, threshold: number | null): string {
  if (threshold === null) return "—";
  if (predicate === "above_threshold") return `> ${threshold}`;
  if (predicate === "below_threshold") return `< ${threshold}`;
  return String(threshold);
}

/** Score each behavioural metric against its registry rule — the same predicate the detector fires. */
export function evaluateBehavioral(
  snapshot: BehavioralSnapshot,
  rules: RuleJSON[],
): BehavioralRow[] {
  const byId = new Map(rules.map((r) => [r.id, r]));
  const rows: BehavioralRow[] = [];
  for (const m of METRICS) {
    const rule = byId.get(m.ruleId);
    if (rule === undefined) continue; // rule not in this registry build (e.g. retired) — skip silently
    const value = m.value(snapshot);
    const ready = m.ready(snapshot);
    rows.push({
      ruleId: m.ruleId,
      label: m.label,
      value,
      ready,
      threshold: rule.threshold,
      predicate: rule.predicate,
      fires: ready && PREDICATES[rule.predicate]([value], rule.threshold),
      floorText: floorText(rule.predicate, rule.threshold),
    });
  }
  return rows;
}

/** A scripted, constant-velocity straight diagonal — the shape a naive automation path traces. */
export function syntheticBotPath(n = 30): PointerSample[] {
  const pts: PointerSample[] = [];
  for (let i = 0; i < n; i++) pts.push({ x: 100 + i * 10, y: 100 + i * 10, t: i * 16 });
  return pts;
}

/** A behavioural snapshot of the synthetic bot path — for the "demo a bot path" button (purely local;
 *  it never touches the real collector or the verdict, only illustrates the floors firing). */
export function syntheticBotSnapshot(): BehavioralSnapshot {
  const path = syntheticBotPath();
  return {
    pointerSamples: path.length,
    keystrokes: 0,
    enoughMotion: true,
    enoughKeys: false,
    mouseEntropy: mouseEntropy(path),
    mouseStraightness: pathStraightness(path),
    mouseVelocityCv: velocityCV(path),
    keystrokeEntropy: 0,
    touchVelocityCv: velocityCV(path), // a constant-velocity diagonal is also a constant-velocity "swipe"
  };
}
