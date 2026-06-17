// collector/types — shared types mirroring contracts/signal.schema.json.
// The Signal envelope and the layer/source vocabularies the collector emits.

export type Layer = "network" | "browser" | "behavioral" | "reputation";

export type Source = "edge" | "collector" | "detector";

export type SignalValue = string | number | boolean | null;

export interface Signal {
  schema_version: string;
  session_id: string;
  layer: Layer;
  kind: string;
  value: SignalValue;
  source: Source;
  observed_at: string;
}

/** A single pointer position sample (x, y in px; t in ms). */
export interface PointerSample {
  x: number;
  y: number;
  t: number;
}

/** The browser globals the collector reads, abstracted so logic is testable without a browser. */
export interface BrowserEnv {
  webdriver: boolean;
  userAgent: string;
  uaDataPlatform: string | null;
  canvasTampered: boolean;
  cdpRuntimeEnabled: boolean;
  pointerEvents: PointerSample[];
}
