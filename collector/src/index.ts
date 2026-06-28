// collector/index — browser entrypoint: snapshot real globals, collect signals, POST to the detector.
// Wires the live DOM/navigator probes into the pure collector; thin glue (tier-2, excluded from coverage).

import { isScrollTeleport } from "./behavioral.js";
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

function computeFpHash(): string | null {
  try {
    // FNV-1a/32 over a canvas-text render folded with the WebGL renderer/vendor — varies per GPU/driver/
    // OS/font-stack, so two real machines hash differently. A reused anti-detect profile hashes identically.
    const c = document.createElement("canvas");
    c.width = 240;
    c.height = 60;
    const x = c.getContext("2d");
    if (x === null) return null;
    x.textBaseline = "alphabetic";
    x.fillStyle = "#f60";
    x.fillRect(125, 1, 62, 20);
    x.fillStyle = "#069";
    x.font = "11pt no-real-font-123";
    x.fillText("Kitsune 🦊 fp ⒶⒷ", 2, 15);
    x.fillStyle = "rgba(102, 204, 0, 0.7)";
    x.font = "18pt Arial";
    x.fillText("Kitsune 🦊 fp ⒶⒷ", 4, 45);
    const px = x.getImageData(0, 0, 240, 60).data;
    let h = 0x811c9dc5;
    for (let i = 0; i < px.length; i += 4) {
      h = Math.imul(h ^ (px[i] ?? 0), 0x01000193) >>> 0;
    }
    const gl = c.getContext("webgl") as WebGLRenderingContext | null;
    let tail = "";
    if (gl !== null) {
      const dbg = gl.getExtension("WEBGL_debug_renderer_info");
      if (dbg !== null) {
        tail =
          `${String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL))}|` +
          `${String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL))}`;
      }
    }
    for (let i = 0; i < tail.length; i += 1) {
      h = Math.imul(h ^ tail.charCodeAt(i), 0x01000193) >>> 0;
    }
    return `0000000${h.toString(16)}`.slice(-8);
  } catch {
    return null;
  }
}

function detectWebdriverSpoofed(): boolean {
  try {
    // Real browsers expose navigator.webdriver via Navigator.prototype; an own property on the instance
    // is a defineProperty patch — the naive way a stealth tool forces navigator.webdriver to false.
    return Object.getOwnPropertyDescriptor(navigator, "webdriver") !== undefined;
  } catch {
    return false;
  }
}

function buildEnv(
  pointerEvents: PointerSample[],
  keyEvents: number[],
  clickEvents: number[],
  scrollTeleport: boolean,
  cdp: CdpProbe,
): BrowserEnv {
  const uaData = (navigator as Navigator & { userAgentData?: NavigatorUAData }).userAgentData;
  return {
    webdriver: navigator.webdriver === true,
    webdriverSpoofed: detectWebdriverSpoofed(),
    userAgent: navigator.userAgent,
    uaDataPlatform: uaData?.platform ?? null,
    canvasTampered: detectCanvasLie(),
    cdpRuntimeEnabled: cdp.triggered(),
    fpHash: computeFpHash(),
    pointerEvents,
    keyEvents,
    clickEvents,
    scrollTeleport,
  };
}

/** Attach listeners and POST a snapshot of collected signals after `delayMs`. */
export function run(detectorUrl: string, delayMs = 4000): void {
  const pointerEvents: PointerSample[] = [];
  const keyEvents: number[] = [];
  const clickEvents: number[] = [];
  const cdp = armCdpProbe();
  // Expose the marker so a CDP Runtime.enable preview enumerates it and trips the trap.
  (globalThis as Record<string, unknown>).__ks = cdp.marker;

  // Scroll-teleport state (radar G14): max single scroll-event delta + wheel count + scroll-key use.
  let maxScrollDelta = 0;
  let lastScrollY = 0;
  let wheelCount = 0;
  let scrollKeyUsed = false;
  const scrollKeys = /^(PageDown|PageUp|Home|End|ArrowDown|ArrowUp|Spacebar| )$/;

  window.addEventListener("pointermove", (e: PointerEvent) => {
    pointerEvents.push({ x: e.clientX, y: e.clientY, t: e.timeStamp });
  });
  window.addEventListener("keydown", (e: KeyboardEvent) => {
    keyEvents.push(e.timeStamp);
    if (scrollKeys.test(e.key)) scrollKeyUsed = true;
  });
  window.addEventListener(
    "scroll",
    () => {
      const y = window.scrollY || document.documentElement.scrollTop || 0;
      const delta = Math.abs(y - lastScrollY);
      if (delta > maxScrollDelta) maxScrollDelta = delta;
      lastScrollY = y;
    },
    { passive: true },
  );
  window.addEventListener("wheel", () => void wheelCount++, { passive: true });

  const post = (): void => {
    const sessionId = readSessionId(document.cookie);
    if (sessionId === null) return;
    const scrollTeleport = isScrollTeleport(
      maxScrollDelta,
      wheelCount,
      scrollKeyUsed,
      navigator.maxTouchPoints || 0,
    );
    const env = buildEnv(pointerEvents, keyEvents, clickEvents, scrollTeleport, cdp);
    void httpTransport(detectorUrl, fetch as unknown as FetchLike).send(collectSignals(sessionId, env, new Date()));
  };
  // Long-horizon re-post (radar G12): action-cadence needs >=5 high-level actions spread over tens of seconds,
  // far beyond the snapshot delay below. Re-post ONCE when the 5th trusted click lands so the accumulated
  // cadence is captured (the snapshot carries too few actions). Bounded to a single extra post.
  let cadencePosted = false;
  window.addEventListener("click", (e: MouseEvent) => {
    if (!e.isTrusted) return;
    clickEvents.push(e.timeStamp);
    if (!cadencePosted && clickEvents.length >= 5) {
      cadencePosted = true;
      post();
    }
  });
  // One-shot re-post when a big instant scroll lands (radar G14) — it may occur after the snapshot delay.
  let scrollPosted = false;
  window.addEventListener(
    "scroll",
    () => {
      if (!scrollPosted && maxScrollDelta >= 800) {
        scrollPosted = true;
        post();
      }
    },
    { passive: true },
  );

  window.setTimeout(post, delayMs);
}
