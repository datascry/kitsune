// collector/test/signal — tests for the Signal envelope builder.
// Asserts contract fields, the collector source, and ISO observed_at.

import { describe, expect, it } from "vitest";
import { SCHEMA_VERSION, makeSignal } from "../src/signal.js";

describe("makeSignal", () => {
  it("builds a contract-shaped signal", () => {
    const at = new Date("2026-06-17T12:00:00Z");
    const sig = makeSignal("sess", "browser", "webdriver", true, at);
    expect(sig).toEqual({
      schema_version: SCHEMA_VERSION,
      session_id: "sess",
      layer: "browser",
      kind: "webdriver",
      value: true,
      source: "collector",
      observed_at: "2026-06-17T12:00:00.000Z",
    });
  });
});
