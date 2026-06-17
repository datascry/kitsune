// collector/test/session — tests for reading the ks_sid correlation cookie.
// Covers presence, absence, multi-cookie strings, and URI decoding.

import { describe, expect, it } from "vitest";
import { readSessionId } from "../src/session.js";

describe("readSessionId", () => {
  it("reads the cookie value", () => {
    expect(readSessionId("ks_sid=abc123")).toBe("abc123");
  });

  it("finds it among other cookies", () => {
    expect(readSessionId("foo=1; ks_sid=xyz; bar=2")).toBe("xyz");
  });

  it("returns null when absent", () => {
    expect(readSessionId("foo=1; bar=2")).toBeNull();
  });

  it("uri-decodes the value", () => {
    expect(readSessionId("ks_sid=a%2Fb")).toBe("a/b");
  });
});
