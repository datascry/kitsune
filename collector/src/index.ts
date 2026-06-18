// collector/index — browser entrypoint: snapshot real globals, collect signals, POST to the detector.
// Wires the live DOM/navigator probes into the pure collector; thin glue (tier-2, excluded from coverage).

import { armCdpProbe, type CdpProbe } from "./cdp.js";
import { collectSignals } from "./collect.js";
import { readSessionId } from "./session.js";
import { httpTransport, type FetchLike } from "./transport.js";
import type { BrowserEnv, PointerSample } from "./types.js";

interface NavigatorUAData {
  platform?: string;
}

function detectCanvasLie(): boolean {
  try {
    // A genuine native method stringifies to "[native code]"; a stealth override does not.
    return !HTMLCanvasElement.prototype.toDataURL.toString().includes("[native code]");
  } catch {
    return true;
  }
}

function buildEnv(pointerEvents: PointerSample[], keyEvents: number[], cdp: CdpProbe): BrowserEnv {
  const uaData = (navigator as Navigator & { userAgentData?: NavigatorUAData }).userAgentData;
  return {
    webdriver: navigator.webdriver === true,
    userAgent: navigator.userAgent,
    uaDataPlatform: uaData?.platform ?? null,
    canvasTampered: detectCanvasLie(),
    cdpRuntimeEnabled: cdp.triggered(),
    pointerEvents,
    keyEvents,
  };
}

/** Attach listeners and POST a snapshot of collected signals after `delayMs`. */
export function run(detectorUrl: string, delayMs = 4000): void {
  const pointerEvents: PointerSample[] = [];
  const keyEvents: number[] = [];
  const cdp = armCdpProbe();
  // Expose the marker so a CDP Runtime.enable preview enumerates it and trips the trap.
  (globalThis as Record<string, unknown>).__ks = cdp.marker;

  window.addEventListener("pointermove", (e: PointerEvent) => {
    pointerEvents.push({ x: e.clientX, y: e.clientY, t: e.timeStamp });
  });
  window.addEventListener("keydown", (e: KeyboardEvent) => {
    keyEvents.push(e.timeStamp);
  });

  window.setTimeout(() => {
    const sessionId = readSessionId(document.cookie);
    if (sessionId === null) return;
    const signals = collectSignals(sessionId, buildEnv(pointerEvents, keyEvents, cdp), new Date());
    void httpTransport(detectorUrl, fetch as unknown as FetchLike).send(signals);
  }, delayMs);
}
