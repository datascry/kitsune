// collector/collect — assemble a session's browser + behavioral signals.
// Pure: takes a BrowserEnv snapshot and emits contract-valid signals (no globals touched).

import {
  keystrokeEntropy,
  keystrokeIntervalMedian,
  mouseEntropy,
  pathStraightness,
  pointerEventCount,
  traceHash,
  velocityCV,
} from "./behavioral.js";
import { isHeadlessUA, normalizePlatform, uaBrowser, uaPlatform } from "./detect.js";
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
  if (env.webdriverSpoofed) {
    out.push(sig("browser", "webdriver_spoofed", true));
  }
  if (env.canvasTampered) {
    out.push(sig("browser", "canvas_lie", true));
  }
  if (env.cdpRuntimeEnabled) {
    out.push(sig("browser", "cdp_runtime_enabled", true));
  }
  if (isHeadlessUA(env.userAgent)) {
    out.push(sig("browser", "ua_is_headless", true));
  }
  // High-entropy identity. Real machines each hash differently; an identical fp_hash across distinct IPs
  // is one cloned anti-detect profile (the coordination scorer's profile-reuse tell). Absent if uncomputed.
  if (env.fpHash !== null) {
    out.push(sig("browser", "fp_hash", env.fpHash));
  }

  out.push(sig("behavioral", "mouse_entropy", mouseEntropy(env.pointerEvents)));
  out.push(sig("behavioral", "pointer_event_count", pointerEventCount(env.pointerEvents)));
  out.push(sig("behavioral", "keystroke_entropy", keystrokeEntropy(env.keyEvents)));
  const keyIntervalMs = keystrokeIntervalMedian(env.keyEvents);
  if (keyIntervalMs >= 0) out.push(sig("behavioral", "keystroke_interval_ms", keyIntervalMs));
  // Shape features need a real path; emit only with enough samples (else genuinely absent).
  if (env.pointerEvents.length >= 3) {
    out.push(sig("behavioral", "mouse_straightness", pathStraightness(env.pointerEvents)));
    out.push(sig("behavioral", "mouse_velocity_cv", velocityCV(env.pointerEvents)));
  }
  // Trajectory identity. Two real users never trace the same path; an identical trace_hash across distinct
  // IPs is one tool replaying a canned trajectory (the behavioural analog of fp_hash). Absent below a floor.
  const th = traceHash(env.pointerEvents);
  if (th !== null) {
    out.push(sig("behavioral", "trace_hash", th));
  }
  return out;
}
