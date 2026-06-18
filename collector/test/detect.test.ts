// collector/test/detect — tests for UA/Client-Hints label derivation.
// Covers browser/platform classification and Client-Hints platform normalisation.

import { describe, expect, it } from "vitest";
import { isHeadlessUA, normalizePlatform, uaBrowser, uaPlatform } from "../src/detect.js";

const CHROME =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML) Chrome/125.0 Safari/537.36";
const FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0";
const EDGE =
  "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/125.0 Safari/537.36 Edg/125.0";
const SAFARI =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15";

describe("uaBrowser", () => {
  it.each([
    [CHROME, "chrome"],
    [FIREFOX, "firefox"],
    [EDGE, "edge"],
    [SAFARI, "safari"],
    ["weird-bot/1.0", "unknown"],
  ])("classifies %s", (ua, expected) => {
    expect(uaBrowser(ua)).toBe(expected);
  });
});

describe("uaPlatform", () => {
  it.each([
    [CHROME, "Windows"],
    [SAFARI, "macOS"],
    ["Mozilla/5.0 (Linux; Android 14)", "Android"],
    [FIREFOX, "Linux"],
    ["nothing", "unknown"],
  ])("classifies %s", (ua, expected) => {
    expect(uaPlatform(ua)).toBe(expected);
  });
});

describe("normalizePlatform", () => {
  it("maps known and passes through unknown", () => {
    expect(normalizePlatform("Mac OS X")).toBe("macOS");
    expect(normalizePlatform("Windows")).toBe("Windows");
    expect(normalizePlatform("Chrome OS")).toBe("Chrome OS");
  });
});

describe("isHeadlessUA", () => {
  it("flags headless user-agents", () => {
    expect(isHeadlessUA("Mozilla/5.0 HeadlessChrome/125.0")).toBe(true);
    expect(isHeadlessUA(CHROME)).toBe(false);
  });
});
