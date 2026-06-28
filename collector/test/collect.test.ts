// collector/test/collect — tests for assembling a session's signals from a BrowserEnv.
// Covers conditional emission of ch_platform / canvas_lie / cdp / headless tells (clean vs bot env).

import { describe, expect, it } from "vitest";
import { collectSignals } from "../src/collect.js";
import type { BrowserEnv } from "../src/types.js";

const NOW = new Date("2026-06-17T12:00:00Z");

const cleanEnv: BrowserEnv = {
  webdriver: false,
  webdriverSpoofed: false,
  userAgent: "Mozilla/5.0 (Windows NT 10.0) Chrome/125.0 Safari/537.36",
  uaDataPlatform: null,
  canvasTampered: false,
  cdpRuntimeEnabled: false,
  fpHash: null,
  pointerEvents: [],
  keyEvents: [],
  clickEvents: [],
  scrollTeleport: false,
};

const botEnv: BrowserEnv = {
  webdriver: true,
  webdriverSpoofed: true,
  userAgent: "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/125.0 Safari/537.36",
  uaDataPlatform: "Linux",
  canvasTampered: true,
  cdpRuntimeEnabled: true,
  fpHash: "deadbeef",
  pointerEvents: [],
  keyEvents: [],
  clickEvents: [],
  scrollTeleport: false,
};

function kinds(env: BrowserEnv): string[] {
  return collectSignals("s", env, NOW).map((sig) => sig.kind);
}

describe("collectSignals", () => {
  it("emits only the always-on signals for a clean env", () => {
    expect(kinds(cleanEnv)).toEqual([
      "webdriver",
      "ua_browser",
      "ua_platform",
      "mouse_entropy",
      "pointer_event_count",
      "keystroke_entropy",
    ]);
  });

  it("emits the tell signals for a bot env", () => {
    const k = kinds(botEnv);
    expect(k).toContain("ch_platform");
    expect(k).toContain("webdriver_spoofed");
    expect(k).toContain("canvas_lie");
    expect(k).toContain("cdp_runtime_enabled");
    expect(k).toContain("ua_is_headless");
    expect(k).toContain("fp_hash");
  });

  it("omits fp_hash when it could not be computed (null)", () => {
    expect(kinds(cleanEnv)).not.toContain("fp_hash");
  });

  it("stamps session id and collector source", () => {
    const sigs = collectSignals("sess-1", cleanEnv, NOW);
    expect(sigs.every((s) => s.session_id === "sess-1" && s.source === "collector")).toBe(true);
  });
});

describe("collectSignals action cadence (radar G12)", () => {
  it("emits action_cadence_deliberative for metronomic multi-second clicks (LLM think-time)", () => {
    // 6 clicks ~5s apart with small jitter → median ~5s, low CV → the deliberative agent cadence.
    const env: BrowserEnv = { ...cleanEnv, clickEvents: [0, 5000, 9800, 15100, 19900, 25200] };
    expect(collectSignals("s", env, NOW).map((s) => s.kind)).toContain("action_cadence_deliberative");
  });
  it("does NOT emit it for bursty human clicks (high variance)", () => {
    // human: irregular sub-second-to-few-second gaps → CV well above 0.35.
    const env: BrowserEnv = { ...cleanEnv, clickEvents: [0, 200, 450, 3500, 3700, 9000] };
    expect(collectSignals("s", env, NOW).map((s) => s.kind)).not.toContain("action_cadence_deliberative");
  });
  it("emits scroll_teleport when the env flags a programmatic scroll jump (radar G14)", () => {
    const env: BrowserEnv = { ...cleanEnv, scrollTeleport: true };
    expect(collectSignals("s", env, NOW).map((s) => s.kind)).toContain("scroll_teleport");
    expect(collectSignals("s", cleanEnv, NOW).map((s) => s.kind)).not.toContain("scroll_teleport");
  });
});

describe("collectSignals shape features", () => {
  it("emits straightness + velocity only when a path exists", () => {
    const env: BrowserEnv = {
      ...cleanEnv,
      pointerEvents: [
        { x: 0, y: 0, t: 0 },
        { x: 5, y: 5, t: 1 },
        { x: 10, y: 0, t: 2 },
      ],
    };
    const k = collectSignals("s", env, NOW).map((s) => s.kind);
    expect(k).toContain("mouse_straightness");
    expect(k).toContain("mouse_velocity_cv");
    // the no-path clean env must NOT emit them
    expect(collectSignals("s", cleanEnv, NOW).map((s) => s.kind)).not.toContain(
      "mouse_straightness",
    );
  });
});
