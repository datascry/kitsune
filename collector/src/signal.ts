// collector/signal — build contract-valid Signal envelopes.
// Stamps schema_version + source=collector; serialises observed_at as ISO-8601.

import type { Layer, Signal, SignalValue } from "./types.js";

export const SCHEMA_VERSION = "0.1";

export function makeSignal(
  sessionId: string,
  layer: Layer,
  kind: string,
  value: SignalValue,
  observedAt: Date,
): Signal {
  return {
    schema_version: SCHEMA_VERSION,
    session_id: sessionId,
    layer,
    kind,
    value,
    source: "collector",
    observed_at: observedAt.toISOString(),
  };
}
