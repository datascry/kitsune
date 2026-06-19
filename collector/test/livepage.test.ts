// collector/test/livepage — parity tests for the in-browser coherence engine.
// Asserts predicates, noisy-or scoring + incoherence amplification, and rule evaluation match the detector.

import { describe, expect, it } from "vitest";
import {
  type Contradiction,
  evaluate,
  type SignalMap,
  verdictFor,
} from "../src/livepage/engine.js";
import { MISSING, PREDICATES, type Resolved } from "../src/livepage/predicates.js";
import { notApplicable, type Prediction } from "../src/livepage/predict.js";
import type { RuleJSON } from "../src/livepage/registry.js";
import {
  finalScore,
  incoherenceScore,
  labelFor,
  layerScores,
  noisyOr,
} from "../src/livepage/scoring.js";

describe("predicates", () => {
  const run = (
    name: keyof typeof PREDICATES,
    values: Resolved[],
    t: number | null = null,
  ): boolean => PREDICATES[name](values, t);

  it("present fires on a truthy value, not on MISSING/falsy", () => {
    expect(run("present", [true])).toBe(true);
    expect(run("present", ["x"])).toBe(true);
    expect(run("present", [false])).toBe(false);
    expect(run("present", [MISSING])).toBe(false);
    expect(run("present", [])).toBe(false);
  });

  it("absent is the negation of present", () => {
    expect(run("absent", [MISSING])).toBe(true);
    expect(run("absent", [false])).toBe(true);
    expect(run("absent", [true])).toBe(false);
  });

  it("equals fires only when both sides present and equal", () => {
    expect(run("equals", ["a", "a"])).toBe(true);
    expect(run("equals", ["a", "b"])).toBe(false);
    expect(run("equals", ["a", MISSING])).toBe(false);
    expect(run("equals", [null, null])).toBe(true);
  });

  it("not_equal fires only when both present and differ (missing-safe)", () => {
    expect(run("not_equal", ["a", "b"])).toBe(true);
    expect(run("not_equal", ["a", "a"])).toBe(false);
    expect(run("not_equal", ["a", MISSING])).toBe(false);
    expect(run("not_equal", [MISSING, MISSING])).toBe(false);
  });

  it("thresholds fire on numbers only, never booleans, and need a threshold", () => {
    expect(run("below_threshold", [0.1], 0.15)).toBe(true);
    expect(run("below_threshold", [0.2], 0.15)).toBe(false);
    expect(run("below_threshold", [0.1], null)).toBe(false);
    expect(run("below_threshold", [true], 0.15)).toBe(false);
    expect(run("above_threshold", [0.98], 0.97)).toBe(true);
    expect(run("above_threshold", [0.5], 0.97)).toBe(false);
    expect(run("above_threshold", [MISSING], 0.97)).toBe(false);
  });
});

describe("scoring", () => {
  it("noisyOr combines independent weights and is 0 for none", () => {
    expect(noisyOr([])).toBe(0);
    expect(noisyOr([0.5])).toBeCloseTo(0.5);
    expect(noisyOr([0.5, 0.5])).toBeCloseTo(0.75);
  });

  const single = (layers: Contradiction["layers"], weight: number): Contradiction[] => [
    { id: "x", title: "t", layers, weight, category: "c", evidence: [] },
  ];

  it("amplifies cross-layer contradictions in the final score", () => {
    // single-layer: raw weight; cross-layer: weight * 1.5 (capped at 1.0)
    expect(finalScore(single(["browser"], 0.6))).toBeCloseTo(0.6);
    expect(finalScore(single(["browser", "network"], 0.6))).toBeCloseTo(0.9);
    expect(finalScore(single(["browser", "network"], 0.8))).toBeCloseTo(1.0);
  });

  it("incoherenceScore counts only cross-layer contradictions", () => {
    expect(incoherenceScore(single(["browser"], 0.6))).toBe(0);
    expect(incoherenceScore(single(["browser", "network"], 0.6))).toBeCloseTo(0.6);
  });

  it("layerScores buckets raw weights per touched layer", () => {
    const s = layerScores(single(["browser", "behavioral"], 0.6));
    expect(s.browser).toBeCloseTo(0.6);
    expect(s.behavioral).toBeCloseTo(0.6);
    expect(s.network).toBe(0);
  });

  it("labelFor uses the detector thresholds", () => {
    expect(labelFor(0.7)).toBe("bot");
    expect(labelFor(0.4)).toBe("suspicious");
    expect(labelFor(0.1)).toBe("human");
  });

  it("conviction gate: corroborating-only tells never reach bot, even at a bot-level score", () => {
    // The real-browser FP: a stripped-but-real browser noisy-or's a few environment tells past the bot
    // threshold. With the gate it caps at `suspicious` — only a convicting category can label `bot`.
    const env: Contradiction[] = [
      {
        id: "a",
        title: "",
        layers: ["browser"],
        weight: 0.6,
        category: "environment",
        evidence: [],
      },
      {
        id: "b",
        title: "",
        layers: ["browser"],
        weight: 0.6,
        category: "behavioral",
        evidence: [],
      },
    ];
    expect(finalScore(env)).toBeGreaterThanOrEqual(0.65); // would be `bot` under a bare threshold
    expect(labelFor(finalScore(env), env)).toBe("suspicious");
    // A single convicting (coherence/automation/artifact) tell unlocks `bot`.
    const convicting: Contradiction[] = [
      {
        id: "c",
        title: "",
        layers: ["browser"],
        weight: 0.7,
        category: "automation",
        evidence: [],
      },
    ];
    expect(labelFor(finalScore(convicting), convicting)).toBe("bot");
    expect(verdictFor(env).label).toBe("suspicious");
  });
});

describe("evaluate", () => {
  const rule = (over: Partial<RuleJSON>): RuleJSON => ({
    id: "br.webdriver",
    title: "webdriver present",
    layers: ["browser"],
    reads: ["browser.webdriver"],
    predicate: "present",
    threshold: null,
    weight: 0.9,
    category: "automation",
    status: "active",
    clientEvaluable: true,
    ...over,
  });

  it("fires rules whose predicate holds over resolved signals", () => {
    const signals: SignalMap = new Map([["browser.webdriver", true]]);
    const out = evaluate([rule({})], signals);
    expect(out).toHaveLength(1);
    expect(out[0]?.id).toBe("br.webdriver");
    expect(out[0]?.evidence).toEqual(["browser.webdriver"]);
  });

  it("does not fire when the read signal is missing", () => {
    expect(evaluate([rule({})], new Map())).toHaveLength(0);
  });

  it("verdictFor assembles a full verdict from contradictions", () => {
    const signals: SignalMap = new Map([["browser.webdriver", true]]);
    const v = verdictFor(evaluate([rule({})], signals));
    expect(v.label).toBe("bot");
    expect(v.score).toBeCloseTo(0.9);
    expect(v.layers.browser).toBeCloseTo(0.9);
    expect(v.contradictions).toHaveLength(1);
  });
});

describe("per-browser applicability (notApplicable) — lowers false positives", () => {
  const pred = (o: Partial<Prediction>): Prediction => ({
    engine: "blink",
    browser: "Chrome",
    os: "Windows",
    formFactor: "desktop",
    confidence: 1,
    evidence: [],
    ...o,
  });

  it("excludes platform-coherence on mobile — the navplatform mobile FP (73% on real traffic)", () => {
    expect(
      notApplicable("br.navplatform_vs_ua", pred({ formFactor: "mobile", os: "Android" })),
    ).not.toBeNull();
    expect(notApplicable("br.webgl_os_vs_ua", pred({ formFactor: "mobile" }))).not.toBeNull();
    expect(notApplicable("br.oscpu_vs_ua", pred({ formFactor: "mobile" }))).not.toBeNull();
  });

  it("applies platform-coherence on desktop (a Windows-UA-on-Linux spoof must still convict)", () => {
    expect(notApplicable("br.navplatform_vs_ua", pred({ formFactor: "desktop" }))).toBeNull();
  });

  it("excludes Chromium-only capability tells on non-blink engines", () => {
    expect(
      notApplicable("br.no_chrome_object", pred({ engine: "gecko", browser: "Firefox" })),
    ).not.toBeNull();
    expect(
      notApplicable("br.no_connection", pred({ engine: "webkit", browser: "Safari" })),
    ).not.toBeNull();
    expect(notApplicable("br.no_chrome_object", pred({ engine: "blink" }))).toBeNull();
  });

  it("never gates an unrelated detection (a true tell still counts)", () => {
    expect(notApplicable("br.webdriver_present", pred({ formFactor: "mobile" }))).toBeNull();
  });
});
