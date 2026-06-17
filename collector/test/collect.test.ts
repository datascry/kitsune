// collector/test/collect — tests for assembling a session's signals from a BrowserEnv.
// Covers conditional emission of ch_platform / canvas_lie / cdp tells (clean vs bot env).

import { describe, expect, it } from "vitest";
import { collectSignals } from "../src/collect.js";
import type { BrowserEnv } from "../src/types.js";

const NOW = new Date("2026-06-17T12:00:00Z");

const cleanEnv: BrowserEnv = {
  webdriver: false,
  userAgent: "Mozilla/5.0 (Windows NT 10.0) Chrome/125.0 Safari/537.36",
  uaDataPlatform: null,
  canvasTampered: false,
  cdpRuntimeEnabled: false,
  pointerEvents: [],
};

const botEnv: BrowserEnv = {
  webdriver: true,
  userAgent: "Mozilla/5.0 (X11; Linux x86_64) Firefox/127.0",
  uaDataPlatform: "Linux",
  canvasTampered: true,
  cdpRuntimeEnabled: true,
  pointerEvents: [],
};

function kinds(env: BrowserEnv): string[] {
  return collectSignals("s", env, NOW).map((sig) => sig.kind);
}

describe("collectSignals", () => {
  it("emits only the always-on signals for a clean env", () => {
    const k = kinds(cleanEnv);
    expect(k).toEqual([
      "webdriver",
      "ua_browser",
      "ua_platform",
      "mouse_entropy",
      "pointer_event_count",
    ]);
  });

  it("emits the tell signals for a bot env", () => {
    const k = kinds(botEnv);
    expect(k).toContain("ch_platform");
    expect(k).toContain("canvas_lie");
    expect(k).toContain("cdp_runtime_enabled");
  });

  it("stamps session id and collector source", () => {
    const sigs = collectSignals("sess-1", cleanEnv, NOW);
    expect(sigs.every((s) => s.session_id === "sess-1" && s.source === "collector")).toBe(true);
  });
});
