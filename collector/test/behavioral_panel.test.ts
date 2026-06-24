// collector/test/behavioral_panel — the live behavioural panel scores metrics against the REAL registry floors.
// Asserts the human path stays clear, the synthetic bot path trips every floor, and below-floor rows stay pending.

import { describe, expect, it } from "vitest";
import {
  type BehavioralRow,
  evaluateBehavioral,
  syntheticBotSnapshot,
} from "../src/livepage/behavioral_metrics.js";
import type { BehavioralSnapshot } from "../src/livepage/probes.js";
import type { RuleJSON } from "../src/livepage/registry.js";

// The four behavioural floors the panel surfaces, with the registry thresholds/predicates they ship with.
const RULES: RuleJSON[] = [
  bh("bh.input_entropy_floor", "below_threshold", 0.15),
  bh("bh.path_too_straight", "above_threshold", 0.97),
  bh("bh.uniform_velocity", "below_threshold", 0.08),
  bh("bh.keystroke_entropy_floor", "below_threshold", 0.15),
  bh("bh.touch_uniform_velocity", "below_threshold", 0.15),
];

function bh(id: string, predicate: RuleJSON["predicate"], threshold: number): RuleJSON {
  return {
    id,
    title: id,
    layers: ["behavioral"],
    reads: [`behavioral.${id}`],
    predicate,
    threshold,
    weight: 0.55,
    category: "behavioral",
    status: "active",
    clientEvaluable: true,
  };
}

function row(rows: BehavioralRow[], id: string): BehavioralRow {
  const r = rows.find((x) => x.ruleId === id);
  if (r === undefined) throw new Error(`no row for ${id}`);
  return r;
}

const HUMAN: BehavioralSnapshot = {
  pointerSamples: 40,
  keystrokes: 8,
  enoughMotion: true,
  enoughKeys: true,
  mouseEntropy: 0.7, // varied direction
  mouseStraightness: 0.4, // curving path
  mouseVelocityCv: 0.6, // variable speed
  keystrokeEntropy: 0.6, // varied cadence
  touchVelocityCv: 0.6, // a varied human swipe
};

describe("evaluateBehavioral", () => {
  it("a varied human snapshot trips no floor", () => {
    const rows = evaluateBehavioral(HUMAN, RULES);
    expect(rows).toHaveLength(5);
    expect(rows.every((r) => r.ready)).toBe(true);
    expect(rows.some((r) => r.fires)).toBe(false);
  });

  it("the synthetic bot path trips every mouse biomech floor", () => {
    const rows = evaluateBehavioral(syntheticBotSnapshot(), RULES);
    // A straight, constant-velocity diagonal: zero direction entropy, straightness 1, zero velocity CV.
    expect(row(rows, "bh.input_entropy_floor").fires).toBe(true);
    expect(row(rows, "bh.path_too_straight").fires).toBe(true);
    expect(row(rows, "bh.uniform_velocity").fires).toBe(true);
  });

  it("uses the rule's own predicate + threshold (the floor text reflects the direction)", () => {
    const rows = evaluateBehavioral(HUMAN, RULES);
    expect(row(rows, "bh.input_entropy_floor").floorText).toBe("< 0.15");
    expect(row(rows, "bh.path_too_straight").floorText).toBe("> 0.97");
  });

  it("below the data floor a metric is not ready and never fires", () => {
    const quiet: BehavioralSnapshot = {
      ...HUMAN,
      enoughMotion: false,
      enoughKeys: false,
      mouseEntropy: 0, // would trip the floor IF judged — but no motion yet, so it must not
      keystrokeEntropy: 0,
      touchVelocityCv: -1, // no swipe measured yet → the touch metric is not ready
    };
    const rows = evaluateBehavioral(quiet, RULES);
    expect(row(rows, "bh.input_entropy_floor").ready).toBe(false);
    expect(row(rows, "bh.input_entropy_floor").fires).toBe(false);
    expect(row(rows, "bh.keystroke_entropy_floor").ready).toBe(false);
  });

  it("skips a metric whose rule is absent from the registry build", () => {
    const rows = evaluateBehavioral(HUMAN, [bh("bh.uniform_velocity", "below_threshold", 0.08)]);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.ruleId).toBe("bh.uniform_velocity");
  });
});

describe("syntheticBotSnapshot", () => {
  it("is a degenerate straight constant-velocity path", () => {
    const s = syntheticBotSnapshot();
    expect(s.enoughMotion).toBe(true);
    expect(s.mouseStraightness).toBeCloseTo(1, 5);
    expect(s.mouseVelocityCv).toBeCloseTo(0, 5);
    expect(s.mouseEntropy).toBeCloseTo(0, 5);
  });
});
