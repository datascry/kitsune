// collector/transport — POST collected signals to the detector's /ingest.
// fetch is injected so the transport is testable without a network or a browser.

import type { Signal } from "./types.js";

export type FetchLike = (
  input: string,
  init: { method: string; headers: Record<string, string>; body: string },
) => Promise<{ ok: boolean }>;

export interface Transport {
  send(signals: Signal[]): Promise<boolean>;
}

export function httpTransport(detectorUrl: string, fetchImpl: FetchLike): Transport {
  return {
    async send(signals: Signal[]): Promise<boolean> {
      const res = await fetchImpl(`${detectorUrl}/ingest`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(signals),
      });
      return res.ok;
    },
  };
}
