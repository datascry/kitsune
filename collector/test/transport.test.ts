// collector/test/transport — tests for posting signals to the detector.
// Uses an injected fetch to assert URL, body, and the ok/!ok result.

import { describe, expect, it, vi } from "vitest";
import { httpTransport, type FetchLike } from "../src/transport.js";
import { makeSignal } from "../src/signal.js";

const signals = [makeSignal("s", "browser", "webdriver", true, new Date("2026-06-17T12:00:00Z"))];

describe("httpTransport", () => {
  it("posts signals to /ingest and returns ok", async () => {
    const fetchImpl = vi.fn<FetchLike>().mockResolvedValue({ ok: true });
    const ok = await httpTransport("http://localhost:8080", fetchImpl).send(signals);

    expect(ok).toBe(true);
    expect(fetchImpl).toHaveBeenCalledOnce();
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe("http://localhost:8080/ingest");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toHaveLength(1);
  });

  it("propagates a non-ok response", async () => {
    const fetchImpl = vi.fn<FetchLike>().mockResolvedValue({ ok: false });
    expect(await httpTransport("http://x", fetchImpl).send(signals)).toBe(false);
  });
});
