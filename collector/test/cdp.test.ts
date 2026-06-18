// collector/test/cdp — tests for the CDP Runtime.enable ownKeys-trap probe.
// Clean env stays false; enumerating the marker (as a CDP preview would) trips the trap.

import { describe, expect, it } from "vitest";
import { armCdpProbe } from "../src/cdp.js";

describe("armCdpProbe", () => {
  it("stays false in a clean environment", () => {
    expect(armCdpProbe().triggered()).toBe(false);
  });

  it("fires when the marker is enumerated (simulating a CDP preview)", () => {
    const probe = armCdpProbe();
    Reflect.ownKeys(probe.marker); // what CDP Runtime.enable does while previewing the object
    expect(probe.triggered()).toBe(true);
  });
});
