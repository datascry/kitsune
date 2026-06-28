// collector/test/behavioral — tests for pointer entropy + event count.
// Asserts the human-entropy floor: straight/absent motion ~0, varied motion high.

import { describe, expect, it } from "vitest";
import {
  actionCadenceDeliberative,
  keystrokeEntropy,
  keystrokeIntervalMedian,
  mouseEntropy,
  pathStraightness,
  pointerEventCount,
  traceHash,
  velocityCV,
} from "../src/behavioral.js";
import type { PointerSample } from "../src/types.js";

const p = (x: number, y: number, t: number): PointerSample => ({ x, y, t });

describe("traceHash", () => {
  const path = (seed: number): PointerSample[] =>
    Array.from({ length: 14 }, (_, i) => p(i * 7 + seed, i * 3, i));

  it("returns null below the movement floor", () => {
    expect(traceHash([p(0, 0, 0), p(1, 1, 1)])).toBeNull();
  });
  it("is identical for the same trajectory (a replayed canned trace collides)", () => {
    expect(traceHash(path(0))).toBe(traceHash(path(0)));
  });
  it("differs for distinct trajectories (real users never collide)", () => {
    expect(traceHash(path(0))).not.toBe(traceHash(path(1)));
  });
  it("ignores timing — only the spatial shape matters", () => {
    const a = path(0);
    const b = a.map((s) => ({ ...s, t: s.t * 13 + 5 }));
    expect(traceHash(a)).toBe(traceHash(b));
  });
});

describe("pointerEventCount", () => {
  it("counts samples", () => {
    expect(pointerEventCount([p(0, 0, 0), p(1, 1, 1)])).toBe(2);
  });
});

describe("mouseEntropy", () => {
  it("is 0 for too few samples", () => {
    expect(mouseEntropy([p(0, 0, 0), p(1, 0, 1)])).toBe(0);
  });

  it("is 0 for a straight line (single direction)", () => {
    const line = [p(0, 0, 0), p(1, 0, 1), p(2, 0, 2), p(3, 0, 3)];
    expect(mouseEntropy(line)).toBe(0);
  });

  it("is 0 when there is no movement", () => {
    const still = [p(5, 5, 0), p(5, 5, 1), p(5, 5, 2)];
    expect(mouseEntropy(still)).toBe(0);
  });

  it("clamps the boundary angle (pi)", () => {
    // movement straight left then a turn — exercises the idx === BINS clamp without throwing
    const samples = [p(2, 0, 0), p(1, 0, 1), p(1, 1, 2), p(0, 1, 3)];
    expect(mouseEntropy(samples)).toBeGreaterThan(0);
  });

  it("is high for varied (circular) motion", () => {
    const circle: PointerSample[] = [];
    for (let k = 0; k < 16; k++) {
      circle.push(
        p(
          Math.round(Math.cos((k / 16) * 2 * Math.PI) * 100),
          Math.round(Math.sin((k / 16) * 2 * Math.PI) * 100),
          k,
        ),
      );
    }
    expect(mouseEntropy(circle)).toBeGreaterThan(0.5);
  });
});

describe("keystrokeEntropy", () => {
  it("is 0 for too few keys", () => {
    expect(keystrokeEntropy([100, 200])).toBe(0);
  });

  it("is 0 for perfectly constant cadence (scripted)", () => {
    expect(keystrokeEntropy([0, 100, 200, 300, 400])).toBe(0);
  });

  it("is positive for varied human cadence", () => {
    expect(keystrokeEntropy([0, 90, 320, 410, 700, 760, 1300])).toBeGreaterThan(0);
  });
});

describe("keystrokeIntervalMedian", () => {
  it("is -1 for too few intervals to judge", () => {
    expect(keystrokeIntervalMedian([100, 200])).toBe(-1);
  });

  it("returns the median inter-key interval for human cadence", () => {
    // intervals 120,130,140,150 -> median 140
    expect(keystrokeIntervalMedian([0, 120, 250, 390, 540])).toBe(140);
  });

  it("is far below the 30ms floor for agent-speed typing", () => {
    // sub-ms gaps but VARIED (so entropy stays human-like) — the orthogonal G13 tell
    expect(keystrokeIntervalMedian([0, 0.6, 1.3, 2.1, 2.8, 3.4])).toBeLessThan(30);
  });
});

describe("actionCadenceDeliberative (radar G12)", () => {
  it("is true for metronomic multi-second clicks (LLM perceive→reason→act cadence)", () => {
    // 6 clicks ~5s apart with small jitter → median ~5s, CV well under 0.35
    expect(actionCadenceDeliberative([0, 5000, 9800, 15100, 19900, 25200], [])).toBe(true);
  });

  it("is false for bursty human clicks (high variance)", () => {
    expect(actionCadenceDeliberative([0, 200, 450, 3500, 3700, 9000], [])).toBe(false);
  });

  it("is false below 5 actions (too few intervals for a stable CV)", () => {
    expect(actionCadenceDeliberative([0, 5000, 10000, 15000], [])).toBe(false);
  });

  it("is false for sub-second metronomic clicks (fast, not deliberative — median below the band)", () => {
    expect(actionCadenceDeliberative([0, 500, 1000, 1500, 2000, 2500], [])).toBe(false);
  });

  it("folds typing bursts into the action timeline (a keydown >1s after the prior key starts an action)", () => {
    // clicks + two typing-burst starts at metronomic spacing → deliberative
    const keys = [3000, 3050, 3110, 13000, 13040]; // two bursts: starts at 3000 and 13000
    expect(actionCadenceDeliberative([0, 8000, 18000, 23000], keys)).toBe(true);
  });
});

describe("pathStraightness", () => {
  it("is ~1 for a straight line", () => {
    expect(pathStraightness([p(0, 0, 0), p(5, 0, 1), p(10, 0, 2)])).toBeCloseTo(1, 5);
  });
  it("is < 1 for a curved path", () => {
    expect(pathStraightness([p(0, 0, 0), p(5, 5, 1), p(10, 0, 2)])).toBeLessThan(0.95);
  });
  it("is 0 for too few samples or zero-length path", () => {
    expect(pathStraightness([p(0, 0, 0), p(1, 1, 1)])).toBe(0);
    expect(pathStraightness([p(2, 2, 0), p(2, 2, 1), p(2, 2, 2)])).toBe(0);
  });
});

describe("velocityCV", () => {
  it("is ~0 for constant speed", () => {
    expect(velocityCV([p(0, 0, 0), p(10, 0, 1), p(20, 0, 2), p(30, 0, 3)])).toBeLessThan(0.01);
  });
  it("is high for variable speed", () => {
    expect(velocityCV([p(0, 0, 0), p(1, 0, 1), p(50, 0, 2), p(52, 0, 3)])).toBeGreaterThan(0.1);
  });
  it("returns 1 when undeterminable", () => {
    expect(velocityCV([p(0, 0, 0)])).toBe(1); // < 2 speeds
    expect(velocityCV([p(5, 5, 0), p(5, 5, 1), p(5, 5, 2)])).toBe(1); // zero mean speed
  });
});
