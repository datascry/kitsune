// collector/collect — assemble a session's browser + behavioral signals.
// Pure: takes a BrowserEnv snapshot and emits contract-valid signals (no globals touched).

import { mouseEntropy, pointerEventCount } from "./behavioral.js";
import { normalizePlatform, uaBrowser, uaPlatform } from "./detect.js";
import { makeSignal } from "./signal.js";
import type { BrowserEnv, Layer, Signal, SignalValue } from "./types.js";

export function collectSignals(sessionId: string, env: BrowserEnv, now: Date): Signal[] {
  const sig = (layer: Layer, kind: string, value: SignalValue): Signal =>
    makeSignal(sessionId, layer, kind, value, now);

  const out: Signal[] = [
    sig("browser", "webdriver", env.webdriver),
    sig("browser", "ua_browser", uaBrowser(env.userAgent)),
    sig("browser", "ua_platform", uaPlatform(env.userAgent)),
  ];

  if (env.uaDataPlatform !== null) {
    out.push(sig("browser", "ch_platform", normalizePlatform(env.uaDataPlatform)));
  }
  // Boolean "tell" signals are only emitted when present, so absence is genuinely absent.
  if (env.canvasTampered) {
    out.push(sig("browser", "canvas_lie", true));
  }
  if (env.cdpRuntimeEnabled) {
    out.push(sig("browser", "cdp_runtime_enabled", true));
  }

  out.push(sig("behavioral", "mouse_entropy", mouseEntropy(env.pointerEvents)));
  out.push(sig("behavioral", "pointer_event_count", pointerEventCount(env.pointerEvents)));
  return out;
}
