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
  /** True if navigator.webdriver is an own property (patched via defineProperty). */
  webdriverSpoofed: boolean;
  userAgent: string;
  uaDataPlatform: string | null;
  canvasTampered: boolean;
  cdpRuntimeEnabled: boolean;
  /** Stable high-entropy fingerprint hash (canvas+WebGL); null if it could not be computed. Identical
   * across a fleet means one cloned anti-detect profile — the coordination scorer keys on the collision. */
  fpHash: string | null;
  pointerEvents: PointerSample[];
  /** Timestamps (ms) of keydown events, for keystroke-dynamics. */
  keyEvents: number[];
  /** Timestamps (ms) of trusted click events — the high-level action timeline for action-cadence (G12). */
  clickEvents: number[];
  /** True if the session scrolled via a big instant programmatic jump (no wheel/key input) — scrollIntoView (G14). */
  scrollTeleport: boolean;
  /** True if a form field's value changed with no keydown on it and no trusted paste — programmatic input (G15). */
  inputViaPaste: boolean;
}
