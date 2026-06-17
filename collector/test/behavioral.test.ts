// collector/test/behavioral — tests for pointer entropy + event count.
// Asserts the human-entropy floor: straight/absent motion ~0, varied motion high.

import { describe, expect, it } from "vitest";
import { mouseEntropy, pointerEventCount } from "../src/behavioral.js";
import type { PointerSample } from "../src/types.js";

const p = (x: number, y: number, t: number): PointerSample => ({ x, y, t });

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
