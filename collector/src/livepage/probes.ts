// collector/livepage/probes — comprehensive in-browser signal collection for the live detection page.
// Faithful TS port of the detector demo page's probes; returns a SignalMap instead of POSTing (tier-2 IO).

import {
  keystrokeEntropy,
  mouseEntropy,
  pathStraightness,
  pointerEventCount,
  velocityCV,
} from "../behavioral.js";
import type { PointerSample, SignalValue } from "../types.js";
import type { SignalMap } from "./engine.js";

// Non-standard / vendor-prefixed surfaces the probes read, typed minimally and reached via unknown casts.
interface UAHEBrand {
  brand?: string;
  version?: string;
}
interface UAData {
  platform?: string;
  brands?: UAHEBrand[];
  getHighEntropyValues?(hints: string[]): Promise<{
    uaFullVersion?: string;
    fullVersionList?: UAHEBrand[];
  }>;
}
interface ExtraNavigator {
  userAgentData?: UAData;
  oscpu?: string;
  deviceMemory?: number;
  connection?: unknown;
}
interface GpuApi {
  requestAdapter(): Promise<GpuAdapter | null>;
}
interface GpuAdapter {
  isFallbackAdapter?: boolean;
  info?: GpuInfo;
  requestAdapterInfo?(): Promise<GpuInfo>;
}
interface GpuInfo {
  vendor?: string;
  architecture?: string;
}
interface OfflineAudioCtor {
  new (channels: number, length: number, sampleRate: number): OfflineAudioContext;
}
interface RtcCtor {
  new (config: { iceServers: { urls: string }[] }): RTCPeerConnection;
}

const nav = (): Navigator & ExtraNavigator => navigator as Navigator & ExtraNavigator;
const win = (): Record<string, unknown> => window as unknown as Record<string, unknown>;

function uaBrowser(ua: string): string {
  if (/Firefox\//.test(ua)) return "firefox";
  if (/Edg\//.test(ua)) return "edge";
  if (/Chrome\//.test(ua)) return "chrome";
  if (/Safari\//.test(ua)) return "safari";
  return "unknown";
}
function uaPlatform(ua: string): string {
  if (/Windows/.test(ua)) return "Windows";
  if (/Macintosh|Mac OS X/.test(ua)) return "macOS";
  if (/Android/.test(ua)) return "Android";
  if (/Linux/.test(ua)) return "Linux";
  return "unknown";
}
function nativeToString(fn: unknown): boolean {
  try {
    return typeof fn === "function" && !fn.toString().includes("[native code]");
  } catch {
    return true;
  }
}
function canvasLie(): boolean {
  return nativeToString(HTMLCanvasElement.prototype.toDataURL);
}
function cdpRuntimeEnabled(): boolean {
  try {
    let detected = false;
    const e = new Error();
    Object.defineProperty(e, "stack", {
      configurable: false,
      enumerable: false,
      get: () => {
        detected = true;
        return "";
      },
    });
    console.debug(e);
    return detected;
  } catch {
    return false;
  }
}
function webglInfo(): { vendor: string; renderer: string } {
  try {
    const gl = document.createElement("canvas").getContext("webgl");
    if (gl === null) return { vendor: "", renderer: "" };
    const ext = gl.getExtension("WEBGL_debug_renderer_info");
    if (ext === null) return { vendor: "", renderer: "" };
    return {
      vendor: String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) ?? ""),
      renderer: String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) ?? ""),
    };
  } catch {
    return { vendor: "", renderer: "" };
  }
}
function toStringTampered(): boolean {
  try {
    const perms = navigator.permissions as { query?: unknown } | undefined;
    const synth = win()["speechSynthesis"] as { getVoices?: unknown } | undefined;
    const md = navigator.mediaDevices as { enumerateDevices?: unknown } | undefined;
    const fns = [
      Function.prototype.toString,
      HTMLCanvasElement.prototype.toDataURL,
      HTMLCanvasElement.prototype.toBlob,
      CanvasRenderingContext2D.prototype.getImageData,
      perms?.query,
      synth?.getVoices,
      md?.enumerateDevices,
    ];
    return fns.some((fn) => fn !== undefined && fn !== null && nativeToString(fn));
  } catch {
    return true;
  }
}
function fontMeasurer(): (font: string) => number {
  const ctx = document.createElement("canvas").getContext("2d");
  const probe = "mmmmmmmmmmlli72px";
  return (font: string): number => {
    if (ctx === null) return 0;
    ctx.font = "72px " + font;
    return ctx.measureText(probe).width;
  };
}
function fontPresent(name: string): boolean {
  try {
    const w = fontMeasurer();
    const bases = ["monospace", "sans-serif", "serif"];
    return bases.some((b) => w(`'${name}',${b}`) !== w(b));
  } catch {
    return false;
  }
}
function fontOSHint(): string {
  try {
    const w = fontMeasurer();
    const bases = ["monospace", "sans-serif", "serif"];
    const baseW = new Map(bases.map((b) => [b, w(b)]));
    const has = (f: string): boolean => bases.some((b) => w(`'${f}',${b}`) !== baseW.get(b));
    const groups: Record<string, string[]> = {
      Windows: ["Segoe UI", "Calibri", "Cambria", "Consolas", "Tahoma"],
      macOS: ["Helvetica Neue", "Lucida Grande", "Geneva", "Menlo", "Monaco"],
      Linux: ["DejaVu Sans", "Liberation Sans", "Ubuntu", "Cantarell", "Noto Sans"],
    };
    let best = "";
    let bestN = 1; // require >= 2 signature fonts before classifying
    for (const [os, fonts] of Object.entries(groups)) {
      const n = fonts.filter(has).length;
      if (n > bestN) {
        bestN = n;
        best = os;
      }
    }
    return best;
  } catch {
    return "";
  }
}
async function permAnomaly(): Promise<boolean> {
  try {
    if (!navigator.permissions || !win()["Notification"]) return false;
    const st = (await navigator.permissions.query({ name: "notifications" as PermissionName }))
      .state;
    return Notification.permission === "denied" && st !== "denied";
  } catch {
    return false;
  }
}
interface AudioResult {
  missing: boolean;
  noise?: boolean;
  value?: number;
}
function audioFP(): Promise<AudioResult> {
  return new Promise((resolve) => {
    try {
      const OAC = (win()["OfflineAudioContext"] ?? win()["webkitOfflineAudioContext"]) as
        | OfflineAudioCtor
        | undefined;
      if (OAC === undefined) {
        resolve({ missing: true });
        return;
      }
      const render = (cb: (sum: number | null) => void): void => {
        const ctx = new OAC(1, 4410, 44100);
        const osc = ctx.createOscillator();
        osc.type = "triangle";
        osc.frequency.value = 10000;
        const comp = ctx.createDynamicsCompressor();
        comp.threshold.value = -50;
        comp.knee.value = 40;
        comp.ratio.value = 12;
        comp.attack.value = 0;
        comp.release.value = 0.25;
        osc.connect(comp);
        comp.connect(ctx.destination);
        osc.start(0);
        ctx
          .startRendering()
          .then((buf) => {
            const data = buf.getChannelData(0);
            let sum = 0;
            for (let i = 0; i < data.length; i++) sum += Math.abs(data[i] ?? 0);
            cb(sum);
          })
          .catch(() => {
            cb(null);
          });
      };
      render((a) => {
        if (a === null) {
          resolve({ missing: true });
          return;
        }
        render((b) => {
          resolve({ missing: false, noise: a !== b, value: a });
        });
      });
    } catch {
      resolve({ missing: true });
    }
  });
}
interface RtcResult {
  any: boolean;
  pub: string | null;
  unavailable: boolean;
}
function webrtcProbe(): Promise<RtcResult> {
  return new Promise((resolve) => {
    let pub: string | null = null;
    let any = false;
    let done = false;
    const finish = (unavailable: boolean): void => {
      if (done) return;
      done = true;
      resolve({ any, pub, unavailable });
    };
    try {
      const RPC = (win()["RTCPeerConnection"] ?? win()["webkitRTCPeerConnection"]) as
        | RtcCtor
        | undefined;
      if (RPC === undefined) {
        finish(true);
        return;
      }
      const pc = new RPC({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
      pc.createDataChannel("ks");
      pc.onicecandidate = (e): void => {
        if (!e.candidate) {
          try {
            pc.close();
          } catch {
            /* already closed */
          }
          finish(false);
          return;
        }
        any = true;
        const c = e.candidate.candidate;
        const m = /([0-9]{1,3}(?:\.[0-9]{1,3}){3})/.exec(c);
        if (m && / typ srflx /.test(c)) pub = m[1] ?? null;
      };
      pc.createOffer()
        .then((o) => pc.setLocalDescription(o))
        .catch(() => {
          /* ignore */
        });
      setTimeout(() => {
        try {
          pc.close();
        } catch {
          /* already closed */
        }
        finish(false);
      }, 700);
    } catch {
      finish(true);
    }
  });
}
function workerNav(): Promise<{ ua: string; hw: number; plat: string; lang: string } | null> {
  return new Promise((resolve) => {
    try {
      const code =
        "onmessage=function(){postMessage({ua:navigator.userAgent," +
        'hw:navigator.hardwareConcurrency,plat:navigator.platform||"",' +
        'lang:(navigator.languages||[]).join(",")})}';
      const w = new Worker(
        URL.createObjectURL(new Blob([code], { type: "application/javascript" })),
      );
      const t = setTimeout(() => {
        resolve(null);
      }, 1500);
      w.onmessage = (
        e: MessageEvent<{ ua: string; hw: number; plat: string; lang: string }>,
      ): void => {
        clearTimeout(t);
        resolve(e.data);
        w.terminate();
      };
      w.postMessage(0);
    } catch {
      resolve(null);
    }
  });
}

/** The WebGL UNMASKED_RENDERER of an OffscreenCanvas inside a Worker. A GPU spoof that patches the main
 * realm's getParameter cannot reach Worker scope, so a Worker reports the real GPU. Returns null on any
 * failure (no OffscreenCanvas/WebGL/debug-info, or timeout) so a missing capability never fires a rule. */
function workerGlRenderer(): Promise<string | null> {
  return new Promise((resolve) => {
    try {
      const code =
        "onmessage=function(){try{" +
        "var c=new OffscreenCanvas(8,8);var gl=c.getContext('webgl');" +
        "var d=gl&&gl.getExtension('WEBGL_debug_renderer_info');" +
        "postMessage(d?String(gl.getParameter(d.UNMASKED_RENDERER_WEBGL)):null);" +
        "}catch(e){postMessage(null);}}";
      const w = new Worker(
        URL.createObjectURL(new Blob([code], { type: "application/javascript" })),
      );
      const t = setTimeout(() => {
        resolve(null);
      }, 1500);
      w.onmessage = (e: MessageEvent<string | null>): void => {
        clearTimeout(t);
        resolve(e.data);
        w.terminate();
      };
      w.postMessage(0);
    } catch {
      resolve(null);
    }
  });
}

// Canvas realm coherence. The same 2D draw ops must hash identically on a main-thread canvas and a
// Worker OffscreenCanvas (one rasterizer + font set). A JS canvas-noise spoof patches the main realm's
// 2D context but cannot reach Worker scope, so the Worker renders clean. The draw is duplicated below —
// CW_DRAW (string, for the Worker) and the inline ops in mainCanvasHashCW MUST stay byte-identical; a
// minified build mangles function names so a shared fn.toString() into the Worker is unsafe.
const CW_DRAW =
  "ctx.textBaseline='top';ctx.font='14px sans-serif';" +
  "ctx.fillStyle='#069';ctx.fillRect(0,0,100,40);" +
  "ctx.fillStyle='#f60';ctx.fillText('Kitsune-CW-7',2,2);" +
  "ctx.strokeStyle='rgba(0,128,0,0.7)';ctx.beginPath();ctx.arc(40,20,15,0,7);ctx.stroke();";

function cwHash(d: Uint8ClampedArray): number {
  let h = 2166136261;
  for (let i = 0; i < d.length; i += 97) h = ((h ^ (d[i] ?? 0)) * 16777619) >>> 0;
  return h;
}

function mainCanvasHashCW(): number | null {
  try {
    const c = document.createElement("canvas");
    c.width = 100;
    c.height = 40;
    const ctx = c.getContext("2d");
    if (ctx === null) return null;
    // keep in sync with CW_DRAW
    ctx.textBaseline = "top";
    ctx.font = "14px sans-serif";
    ctx.fillStyle = "#069";
    ctx.fillRect(0, 0, 100, 40);
    ctx.fillStyle = "#f60";
    ctx.fillText("Kitsune-CW-7", 2, 2);
    ctx.strokeStyle = "rgba(0,128,0,0.7)";
    ctx.beginPath();
    ctx.arc(40, 20, 15, 0, 7);
    ctx.stroke();
    return cwHash(ctx.getImageData(0, 0, 100, 40).data);
  } catch {
    return null;
  }
}

function workerCanvasHashCW(): Promise<number | null> {
  return new Promise((resolve) => {
    try {
      const code =
        "var H=function(d){var h=2166136261;for(var i=0;i<d.length;i+=97){h=((h^(d[i]||0))*16777619)>>>0;}return h;};" +
        "onmessage=function(){try{var c=new OffscreenCanvas(100,40);var ctx=c.getContext('2d');" +
        CW_DRAW +
        "postMessage(H(ctx.getImageData(0,0,100,40).data));}catch(e){postMessage(null);}}";
      const w = new Worker(
        URL.createObjectURL(new Blob([code], { type: "application/javascript" })),
      );
      const t = setTimeout(() => {
        resolve(null);
      }, 1500);
      w.onmessage = (e: MessageEvent<number | null>): void => {
        clearTimeout(t);
        resolve(e.data);
        w.terminate();
      };
      w.postMessage(0);
    } catch {
      resolve(null);
    }
  });
}

/** Timezone (IANA zone + UTC offset) reported inside a Worker. Timezone is a process-level setting, so a
 * real browser — and a legit CDP timezone override — reports it identically in every realm; only a JS
 * main-realm geo-spoof (patching Intl/Date) fails to reach Worker scope. Null on failure → never fires. */
function workerTz(): Promise<{ tz: string; off: number } | null> {
  return new Promise((resolve) => {
    try {
      const code =
        "onmessage=function(){var tz='';try{tz=Intl.DateTimeFormat().resolvedOptions().timeZone||'';}catch(e){}" +
        "postMessage({tz:tz,off:new Date().getTimezoneOffset()});}";
      const w = new Worker(
        URL.createObjectURL(new Blob([code], { type: "application/javascript" })),
      );
      const t = setTimeout(() => {
        resolve(null);
      }, 1500);
      w.onmessage = (e: MessageEvent<{ tz: string; off: number }>): void => {
        clearTimeout(t);
        resolve(e.data);
        w.terminate();
      };
      w.postMessage(0);
    } catch {
      resolve(null);
    }
  });
}

/** A live in-browser collector: arm listeners now, snapshot the full signal set later via collect(). */
export interface LiveCollector {
  collect(): Promise<SignalMap>;
}

/** Attach behavioural listeners and environment baits immediately; collect() snapshots everything. */
export function armCollector(): LiveCollector {
  const pts: PointerSample[] = [];
  const keys: number[] = [];
  let ptrMoves = 0;
  let coalescedMax = 0;
  let cspEnforced = false;
  let voices: SpeechSynthesisVoice[] = [];

  const coalescedSupported =
    typeof PointerEvent !== "undefined" && "getCoalescedEvents" in PointerEvent.prototype;

  addEventListener("mousemove", (e: MouseEvent) => {
    pts.push({ x: e.clientX, y: e.clientY, t: e.timeStamp });
  });
  if (coalescedSupported) {
    addEventListener("pointermove", (e: PointerEvent) => {
      ptrMoves++;
      try {
        const c = e.getCoalescedEvents();
        if (c.length > coalescedMax) coalescedMax = c.length;
      } catch {
        /* ignore */
      }
    });
  }
  addEventListener("keydown", (e: KeyboardEvent) => {
    keys.push(e.timeStamp);
  });
  addEventListener("securitypolicyviolation", () => {
    cspEnforced = true;
  });
  try {
    const csp = new Image();
    csp.src = "data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==";
  } catch {
    /* CSP probe best-effort */
  }
  try {
    const synth = win()["speechSynthesis"] as SpeechSynthesis | undefined;
    if (synth) {
      const grab = (): void => {
        voices = synth.getVoices();
      };
      grab();
      synth.onvoiceschanged = grab;
    }
  } catch {
    /* voices best-effort */
  }

  async function collect(): Promise<SignalMap> {
    const out: SignalMap = new Map();
    const put = (layer: string, kind: string, value: SignalValue): void => {
      out.set(`${layer}.${kind}`, value);
    };
    const ua = navigator.userAgent;

    put("browser", "webdriver", navigator.webdriver === true);
    put("browser", "ua_browser", uaBrowser(ua));
    put("browser", "ua_platform", uaPlatform(ua));

    const uad = nav().userAgentData;
    if (uad?.platform) put("browser", "ch_platform", uad.platform);
    // UA-CH high-entropy coherence (Chromium-only, secure-context): the high-entropy brand list still
    // names HeadlessChrome even when the UA string was cleaned (a deeper headless tell), and its Chrome
    // version must match the UA-string version — a surface UA-spoofers routinely miss.
    if (uad?.getHighEntropyValues) {
      try {
        const he = await uad.getHighEntropyValues(["uaFullVersion", "fullVersionList"]);
        const fvl = he.fullVersionList ?? [];
        const brandList = [...fvl, ...(uad.brands ?? [])];
        if (brandList.some((b) => /headless/i.test(b.brand ?? ""))) {
          put("browser", "ch_he_headless", true);
        }
        const chBrand = fvl.find((b) => /chrom/i.test(b.brand ?? ""));
        const chMajor = (chBrand?.version ?? he.uaFullVersion ?? "").split(".")[0];
        const uaM = /Chrome\/(\d+)/.exec(ua)?.[1];
        if (chMajor && uaM && chMajor !== uaM) put("browser", "ch_he_version_vs_ua", true);
      } catch {
        /* ignore */
      }
    }

    const np = navigator.platform || "";
    const npo = /Mac/i.test(np)
      ? "macOS"
      : /Win/i.test(np)
        ? "Windows"
        : /Linux|X11/i.test(np)
          ? "Linux"
          : /Android/i.test(np)
            ? "Android"
            : "";
    if (npo) put("browser", "nav_platform_os", npo);
    if (canvasLie()) put("browser", "canvas_lie", true);
    if (/Headless/i.test(ua)) put("browser", "ua_is_headless", true);
    if (Object.getOwnPropertyDescriptor(navigator, "webdriver")) {
      put("browser", "webdriver_spoofed", true);
    }

    const wg = webglInfo();
    if (/swiftshader|llvmpipe|software|mesa/i.test(wg.renderer))
      put("browser", "webgl_software", true);
    if (/,\s*or similar|generic renderer|placeholder/i.test(wg.renderer)) {
      put("browser", "webgl_renderer_artifact", true);
    }
    const wo = /Direct3D|D3D[0-9]/i.test(wg.renderer)
      ? "Windows"
      : /Metal|Apple/i.test(wg.renderer)
        ? "macOS"
        : /Vulkan|OpenGL|GLX|Mesa|SwiftShader|llvmpipe/i.test(wg.renderer)
          ? "Linux"
          : "";
    if (wo) put("browser", "webgl_os_hint", wo);
    if (/Chrome|Edg/.test(ua) && !win()["chrome"]) put("browser", "chrome_object_missing", true);
    if (toStringTampered()) put("browser", "function_tostring_tampered", true);
    // Native-function invariants: a real built-in is not a constructor and has no own `prototype`; a Proxy
    // spoof faking the "[native code]" string can violate these. Only flag methods that claim native.
    try {
      const natives: unknown[] = [
        navigator.permissions.query,
        HTMLCanvasElement.prototype.toDataURL,
        navigator.mediaDevices.enumerateDevices,
        WebGLRenderingContext.prototype.getParameter,
        Function.prototype.bind,
      ];
      for (const fn of natives) {
        if (typeof fn !== "function" || !fn.toString().includes("[native code]")) continue;
        if (Object.prototype.hasOwnProperty.call(fn, "prototype")) {
          put("browser", "native_invariant_violated", true);
          break;
        }
        let ctor = false;
        try {
          new (fn as new () => unknown)();
          ctor = true;
        } catch {
          /* native methods correctly throw */
        }
        if (ctor) {
          put("browser", "native_invariant_violated", true);
          break;
        }
      }
    } catch {
      /* ignore */
    }
    // Worker-realm constructor integrity: the realm-coherence rules (worker_divergence, timezone/
    // languages/webgl/canvas_worker_vs_main) all observe a Web Worker, which a tool can only defeat by
    // wrapping window.Worker / OffscreenCanvas to inject its spoof into worker scope. A real browser's
    // global Worker and OffscreenCanvas are native; a wrapped one is a plain function (toString lacks
    // "[native code]"). This closes the escalation path for the entire realm-coherence family.
    if (nativeToString(win()["Worker"]) || nativeToString(win()["OffscreenCanvas"])) {
      put("browser", "worker_constructor_tampered", true);
    }
    // Electron process leak: a renderer exposing a Node `process` is an Electron/automation runtime.
    const proc = (win()["process"] ?? undefined) as
      | { versions?: { electron?: string }; type?: string }
      | undefined;
    if (proc && (proc.versions?.electron || proc.type === "renderer")) {
      put("browser", "electron_process", true);
    }
    // DOMRect invariants: real getBoundingClientRect is deterministic (two reads identical) and a
    // single-rect element's getClientRects()[0] equals it; a noise shim or a one-sided geometry hook breaks
    // these. Verified deterministic + consistent on real Chrome.
    try {
      const dre = document.createElement("div");
      dre.style.cssText =
        "position:absolute;left:-9999px;top:0;width:123.45px;height:67.8px;transform:rotate(7deg) scale(1.3)";
      dre.textContent = "x";
      document.documentElement.appendChild(dre);
      const a = dre.getBoundingClientRect();
      const c = dre.getBoundingClientRect();
      const det = a.x === c.x && a.y === c.y && a.width === c.width && a.height === c.height;
      const rects = dre.getClientRects();
      const r0 = rects[0];
      const cons =
        rects.length === 1 &&
        !!r0 &&
        Math.abs(r0.width - a.width) < 1e-6 &&
        Math.abs(r0.height - a.height) < 1e-6 &&
        Math.abs(r0.x - a.x) < 1e-6 &&
        Math.abs(r0.y - a.y) < 1e-6;
      document.documentElement.removeChild(dre);
      if (!det || !cons) put("browser", "domrect_invariant_violated", true);
    } catch {
      /* ignore */
    }
    // measureText main-vs-OffscreenCanvas coherence: same engine, so identical on a real browser (verified
    // on Chrome). A tool hooking main-thread measureText to spoof fonts but not OffscreenCanvas diverges.
    try {
      if (typeof OffscreenCanvas !== "undefined") {
        const probe = "mmMwWLil10Oo gjpqy 文字";
        const f = "16px sans-serif";
        const main = document.createElement("canvas").getContext("2d");
        const off = new OffscreenCanvas(300, 80).getContext("2d");
        if (main && off) {
          main.font = f;
          off.font = f;
          const m1 = main.measureText(probe);
          const m2 = off.measureText(probe);
          if (m1.width !== m2.width || m1.actualBoundingBoxAscent !== m2.actualBoundingBoxAscent) {
            put("browser", "measuretext_offscreen_divergence", true);
          }
        }
      }
    } catch {
      /* ignore */
    }
    try {
      if (!WebGLRenderingContext.prototype.getParameter.toString().includes("[native code]")) {
        put("browser", "webgl_getparameter_tampered", true);
      }
    } catch {
      /* ignore */
    }
    if (Object.getOwnPropertyDescriptor(navigator, "plugins"))
      put("browser", "plugins_spoofed", true);
    try {
      if (
        ["pdfViewerEnabled", "mimeTypes"].some((p) => Object.getOwnPropertyDescriptor(navigator, p))
      ) {
        put("browser", "nav_property_spoofed", true);
      }
    } catch {
      /* ignore */
    }
    try {
      const wd = Object.getOwnPropertyDescriptor(Navigator.prototype, "webdriver");
      if (wd?.get && !wd.get.toString().includes("[native code]")) {
        put("browser", "webdriver_getter_tampered", true);
      }
    } catch {
      /* ignore */
    }
    try {
      if (win()["Notification"]) {
        const npd = Object.getOwnPropertyDescriptor(Notification, "permission");
        if (npd?.get && !npd.get.toString().includes("[native code]")) {
          put("browser", "notification_getter_tampered", true);
        }
      }
    } catch {
      /* ignore */
    }
    put("browser", "hardware_concurrency", navigator.hardwareConcurrency || 0);
    put("browser", "plugins_count", navigator.plugins.length || 0);
    if (await permAnomaly()) put("browser", "permissions_anomaly", true);

    const uaEngine = /Firefox\//.test(ua)
      ? "firefox"
      : /Edg\/|Chrome\//.test(ua)
        ? "chromium"
        : /Safari\//.test(ua)
          ? "safari"
          : "other";
    put("browser", "ua_engine", uaEngine);
    const ven = navigator.vendor;
    const venEngine = /Google/i.test(ven)
      ? "chromium"
      : ven === ""
        ? "firefox"
        : /Apple/i.test(ven)
          ? "safari"
          : "other";
    put("browser", "vendor_engine", venEngine);
    const hasV8Stack =
      typeof (Error as { captureStackTrace?: unknown }).captureStackTrace === "function";
    if ((uaEngine === "chromium" && !hasV8Stack) || (uaEngine === "firefox" && hasV8Stack)) {
      put("browser", "engine_stack_mismatch", true);
    }
    try {
      const u = undefined as unknown as { x: unknown };
      void u.x;
    } catch (errProbe) {
      const em = errProbe instanceof Error ? errProbe.message : "";
      const errEngine = /Cannot read propert/.test(em)
        ? "chromium"
        : /can't access propert|has no propert/i.test(em)
          ? "firefox"
          : /is not an object/.test(em)
            ? "safari"
            : "";
      if (errEngine && uaEngine !== "other" && errEngine !== uaEngine) {
        put("browser", "error_engine_mismatch", true);
      }
    }
    try {
      const mp = Math.pow(Math.PI, -100).toString();
      const mathEngine =
        mp === "1.9275814160560204e-50"
          ? "chromium"
          : mp === "1.9275814160560206e-50"
            ? "firefox"
            : "";
      if (mathEngine && uaEngine !== "other" && mathEngine !== uaEngine) {
        put("browser", "math_engine_mismatch", true);
      }
    } catch {
      /* ignore */
    }
    const oscpu = nav().oscpu;
    if (oscpu) {
      const oc = /Mac/i.test(oscpu)
        ? "macOS"
        : /Win/i.test(oscpu)
          ? "Windows"
          : /Linux/i.test(oscpu)
            ? "Linux"
            : "";
      if (oc) put("browser", "oscpu_os", oc);
    }
    const isChromium = uaEngine === "chromium";
    // Chrome wraps its WebGL renderer in "ANGLE (...)" on every desktop backend; a bare GPU string under a
    // Chromium UA is the common renderer spoof (real headless Chrome reports "ANGLE (Google, Vulkan ...)").
    if (isChromium && wg.renderer && !/^ANGLE \(/.test(wg.renderer)) {
      put("browser", "webgl_not_angle", true);
    }
    // Stale-template tell: Promise.withResolvers shipped in Chrome 119, so a UA claiming Chrome >=121
    // without it is an engine older than it claims (the JS analog of net.tls_pq_keyshare_vs_ua).
    const uaChrome = parseInt(/Chrome\/(\d+)/.exec(ua)?.[1] ?? "0", 10);
    const hasWithResolvers =
      typeof (Promise as unknown as { withResolvers?: unknown }).withResolvers === "function";
    if (isChromium && uaChrome >= 121 && !hasWithResolvers) {
      put("browser", "engine_feature_vs_ua", true);
    }
    if (isChromium && cdpRuntimeEnabled()) put("browser", "cdp_runtime_enabled", true);
    if (navigator.languages.length === 0) put("browser", "languages_empty", true);
    if (!screen.width || !screen.height || window.outerWidth === 0 || window.outerHeight === 0) {
      put("browser", "screen_zero", true);
    }
    // Raw screen geometry + colour depth as values — feed the prevalence (joint-probability) model.
    if (screen.width && screen.height) {
      put("browser", "screen_resolution", `${screen.width}x${screen.height}`);
    }
    if (screen.colorDepth) put("browser", "color_depth", screen.colorDepth);
    if (screen.availWidth > screen.width || screen.availHeight > screen.height) {
      put("browser", "screen_impossible", true);
    }
    if (isChromium && !nav().connection) put("browser", "chrome_no_connection", true);
    if (isChromium && navigator.pdfViewerEnabled === false)
      put("browser", "chrome_no_pdfviewer", true);
    const chromeObj = win()["chrome"] as { runtime?: unknown } | undefined;
    if (chromeObj && !chromeObj.runtime) put("browser", "chrome_runtime_missing", true);
    if (navigator.mimeTypes.length === 0) put("browser", "mimetypes_empty", true);
    if (isChromium && nav().deviceMemory === undefined)
      put("browser", "chrome_no_devicememory", true);
    try {
      if (win()["Notification"] && Notification.permission === "denied") {
        put("browser", "notification_denied", true);
      }
    } catch {
      /* ignore */
    }
    try {
      const fc = document.createElement("canvas");
      fc.width = 64;
      fc.height = 64;
      const fctx = fc.getContext("2d");
      if (fctx !== null) {
        fctx.fillStyle = "rgb(123, 77, 211)";
        fctx.fillRect(0, 0, 64, 64);
        const fdata = fctx.getImageData(16, 16, 32, 32).data;
        for (let fi = 0; fi < fdata.length; fi += 4) {
          if (
            fdata[fi] !== 123 ||
            fdata[fi + 1] !== 77 ||
            fdata[fi + 2] !== 211 ||
            fdata[fi + 3] !== 255
          ) {
            put("browser", "canvas_noise", true);
            break;
          }
        }
      }
    } catch {
      /* ignore */
    }
    if (navigator.platform === "") put("browser", "platform_empty", true);
    put("browser", "ua_render", uaEngine === "firefox" ? "gecko" : "webkit");
    const ps =
      navigator.productSub === "20030107"
        ? "webkit"
        : navigator.productSub === "20100101"
          ? "gecko"
          : "";
    if (ps) put("browser", "productsub_render", ps);
    const cdcKeys = [
      "$cdc_asdjflasutopfhvcZLmcfl_",
      "__webdriver_evaluate",
      "__selenium_evaluate",
      "__webdriver_script_fn",
      "_Selenium_IDE_Recorder",
      "_phantom",
      "callPhantom",
      "__nightmare",
      "domAutomation",
      "__driver_evaluate",
    ];
    if (cdcKeys.some((k) => k in window || k in document)) put("browser", "cdc_artifacts", true);
    const autoGlobals = [
      "Buffer",
      "process",
      "global",
      "require",
      "__playwright__",
      "__pw_manual",
      "__puppeteer_evaluation_script__",
      "__puppeteer__",
      "_playwright",
      "fmget_targets",
    ];
    let autoHit = autoGlobals.some((k) => k in window);
    try {
      const de = document.documentElement;
      autoHit =
        autoHit || ["webdriver", "selenium", "driver"].some((a) => de.getAttribute(a) !== null);
    } catch {
      /* ignore */
    }
    if (autoHit) put("browser", "automation_globals", true);
    try {
      if (!document.createElement("canvas").getContext("webgl2"))
        put("browser", "webgl2_missing", true);
    } catch {
      /* ignore */
    }
    try {
      const gpu = (navigator as unknown as { gpu?: GpuApi }).gpu;
      if (gpu?.requestAdapter) {
        const adapter = await gpu.requestAdapter();
        let gpuNoHw = false;
        if (!adapter) {
          gpuNoHw = true;
        } else {
          if (adapter.isFallbackAdapter) gpuNoHw = true;
          const ginfo =
            adapter.info ??
            (adapter.requestAdapterInfo ? await adapter.requestAdapterInfo() : null);
          if (ginfo?.vendor) {
            const gpuFam = (s: string): string => {
              const t = s.toLowerCase();
              return /nvidia|geforce|rtx|gtx/.test(t)
                ? "nvidia"
                : /intel|hd graphics|\biris\b|uhd/.test(t)
                  ? "intel"
                  : /\bamd\b|radeon|\bati\b/.test(t)
                    ? "amd"
                    : /apple|\bm1\b|\bm2\b|\bm3\b/.test(t)
                      ? "apple"
                      : /adreno|\bmali\b|powervr/.test(t)
                        ? "mobile"
                        : "";
            };
            const famGL = gpuFam(wg.renderer);
            const famGPU = gpuFam(`${ginfo.vendor} ${ginfo.architecture ?? ""}`);
            if (famGL && famGPU && famGL !== famGPU) put("browser", "webgpu_vendor_mismatch", true);
          }
        }
        const webglHw =
          wg.renderer !== "" &&
          !/swiftshader|llvmpipe|software|mesa|angle \(google/i.test(wg.renderer);
        if (gpuNoHw && webglHw) put("browser", "webgpu_webgl_mismatch", true);
      }
    } catch {
      /* ignore */
    }
    const fo = fontOSHint();
    if (fo) put("browser", "font_os_hint", fo);
    const plat = uaPlatform(ua);
    if (
      plat &&
      plat !== "Linux" &&
      (fontPresent("Arimo") || fontPresent("Cousine") || fontPresent("Tinos"))
    ) {
      put("browser", "font_linux_leak", true);
    }
    if (fontPresent(".Aqua Kana") || fontPresent(".Apple Color Emoji UI")) {
      put("browser", "font_mac_internal", true);
    }
    try {
      if (screen.colorDepth && ![24, 30, 32].includes(screen.colorDepth)) {
        put("browser", "color_depth_anomaly", true);
      }
      if (screen.availWidth > screen.width || screen.availHeight > screen.height) {
        put("browser", "screen_avail_invalid", true);
      }
      if (!(window.devicePixelRatio > 0)) put("browser", "devicepixelratio_anomaly", true);
      const isMobile = /Mobile|Android|iPhone|iPad/i.test(ua);
      if (!isMobile && matchMedia("(hover: none)").matches)
        put("browser", "hover_none_desktop", true);
      const cssTouch = matchMedia("(any-pointer: coarse)").matches;
      const jsTouch = navigator.maxTouchPoints > 0;
      if (cssTouch !== jsTouch) put("browser", "pointer_touch_incoherent", true);
    } catch {
      /* ignore */
    }
    try {
      const synth = win()["speechSynthesis"] as SpeechSynthesis | undefined;
      if (synth) {
        if (voices.length === 0) {
          put("browser", "voices_empty", true);
        } else {
          const names = voices.map((v) => `${v.name} ${v.voiceURI}`).join(" ");
          const voiceOS = /Microsoft|Windows|David|Zira|Hazel/i.test(names)
            ? "Windows"
            : /Apple|Siri|Alex|Samantha|Victoria|macOS/i.test(names)
              ? "macOS"
              : /espeak|eSpeak|Linux/i.test(names)
                ? "Linux"
                : "";
          if (voiceOS) put("browser", "voice_os_hint", voiceOS);
        }
      }
    } catch {
      /* ignore */
    }
    try {
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      if (tz) {
        const dnow = new Date();
        const off = dnow.toLocaleString("en-US", { timeZone: tz, timeZoneName: "longOffset" });
        const m = /GMT([+-]\d{1,2})(?::(\d{2}))?/.exec(off);
        if (m?.[1]) {
          const hh = parseInt(m[1], 10);
          const mm = m[2] ? parseInt(m[2], 10) : 0;
          const implied = -(hh * 60 + (m[1][0] === "-" ? -1 : 1) * mm);
          if (Math.abs(implied - dnow.getTimezoneOffset()) > 1) {
            put("browser", "timezone_inconsistent", true);
          }
        }
        const rfpUTC = tz === "UTC";
        const rfpBox =
          window.innerWidth > 0 && window.innerWidth % 200 === 0 && window.innerHeight % 100 === 0;
        const rfpCores = (navigator.hardwareConcurrency || 99) <= 2;
        if (rfpUTC && rfpBox && rfpCores) put("browser", "rfp_browser", true);
      }
    } catch {
      /* ignore */
    }
    const af = await audioFP();
    if (af.missing) put("browser", "audio_missing", true);
    else if (af.noise) put("browser", "audio_noise", true);
    // Audio readback consistency: getChannelData and copyFromChannel read the same buffer, so on a real
    // engine they are bit-identical (verified diff=0 on Chrome). A farbling shim that perturbs one path
    // diverges — corroborating (fires on Brave/Camoufox privacy farbling too).
    try {
      const OAC = (win()["OfflineAudioContext"] ?? win()["webkitOfflineAudioContext"]) as
        | OfflineAudioCtor
        | undefined;
      if (OAC) {
        const buf = new OAC(1, 2048, 44100).createBuffer(1, 2048, 44100);
        const chan = buf.getChannelData(0);
        for (let i = 0; i < 2048; i++) chan[i] = Math.sin(i / 10);
        const copy = new Float32Array(2048);
        buf.copyFromChannel(copy, 0);
        let diff = 0;
        for (let i = 0; i < 2048; i++) if (chan[i] !== copy[i]) diff++;
        if (diff > 0) put("browser", "audio_readback_noise", true);
      }
    } catch {
      /* ignore */
    }
    const rtc = await webrtcProbe();
    if (rtc.unavailable || !rtc.any) put("browser", "webrtc_unavailable", true);
    try {
      if (navigator.mediaDevices.enumerateDevices) {
        const devs = await navigator.mediaDevices.enumerateDevices();
        if (devs.length === 0) put("browser", "media_devices_empty", true);
      }
    } catch {
      /* ignore */
    }
    try {
      const vEl = document.createElement("video");
      const aEl = document.createElement("audio");
      const h264 = vEl.canPlayType('video/mp4; codecs="avc1.42E01E"');
      const aac = aEl.canPlayType('audio/mp4; codecs="mp4a.40.2"');
      if (plat && plat !== "Linux" && h264 === "" && aac === "") {
        put("browser", "codec_os_incoherent", true);
      }
    } catch {
      /* ignore */
    }
    if (uaPlatform(ua) === "macOS" && window.devicePixelRatio === 1)
      put("browser", "macos_dpr1", true);
    try {
      const ifr = document.createElement("iframe");
      ifr.style.display = "none";
      document.body.appendChild(ifr);
      if (ifr.contentWindow && ifr.contentWindow.navigator.userAgent !== navigator.userAgent) {
        put("browser", "iframe_divergence", true);
      }
      document.body.removeChild(ifr);
    } catch {
      /* ignore */
    }
    const wn = await workerNav();
    if (
      wn &&
      (wn.ua !== navigator.userAgent ||
        wn.hw !== navigator.hardwareConcurrency ||
        (wn.plat && navigator.platform && wn.plat !== navigator.platform))
    ) {
      put("browser", "worker_divergence", true);
    }
    // Language realm coherence: navigator.languages must agree across the main thread and a Worker. A
    // residential-proxy geo-spoof patches navigator.languages in the main realm to match the proxy's
    // country but a JS patch never reaches Worker scope. Only fire when both report a non-empty list and
    // they differ. (Experimental: a legit CDP locale override does NOT propagate to the Worker, so it
    // diverges too — kept corroborating until real-traffic FP-validated.)
    if (
      wn &&
      wn.lang &&
      navigator.languages.length > 0 &&
      wn.lang !== navigator.languages.join(",")
    ) {
      put("browser", "languages_worker_divergence", true);
    }
    // GPU realm coherence: the WebGL renderer must agree across the main thread and a Worker's
    // OffscreenCanvas (one physical GPU). A getParameter spoof patches the main realm but never reaches
    // Worker scope, so a Worker reports the real GPU. Only fire when both report a renderer and they
    // differ — a missing capability (null) never fires.
    const wglr = await workerGlRenderer();
    if (wglr && wg.renderer && wglr !== wg.renderer) {
      put("browser", "webgl_worker_divergence", true);
    }
    // Canvas realm coherence: the same draw must hash identically on the main canvas and a Worker
    // OffscreenCanvas. A main-realm canvas-noise spoof cannot reach the Worker → divergence. Only fire
    // when both hashes are present and differ (a missing capability is null → never fires).
    const mch = mainCanvasHashCW();
    const wch = await workerCanvasHashCW();
    if (mch !== null && wch !== null && mch !== wch) {
      put("browser", "canvas_worker_divergence", true);
    }
    // Timezone realm coherence: a process-level setting is identical in every realm (a legit CDP override
    // reaches the Worker too); only a JS main-realm geo-spoof (Intl/Date) fails to. Fire when the Worker
    // reports a timezone and its UTC offset or IANA zone differs from the main thread.
    let mainTz = "";
    try {
      mainTz = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
    } catch {
      /* ignore */
    }
    const mainOff = new Date().getTimezoneOffset();
    const wtz = await workerTz();
    if (wtz && (wtz.off !== mainOff || (mainTz !== "" && wtz.tz !== "" && wtz.tz !== mainTz))) {
      put("browser", "timezone_worker_divergence", true);
    }
    // Internal timezone coherence: getTimezoneOffset() and the IANA zone (resolvedOptions) both derive from
    // one OS setting, so the zone's current UTC offset must equal -getTimezoneOffset(). A naive geo-spoof
    // patches one field and forgets the other. A legit CDP timezone override keeps both consistent (grounded
    // — the whole Intl/Date engine moves together), so this fires only on a partial JS spoof.
    try {
      if (mainTz !== "") {
        const tzParts = new Intl.DateTimeFormat("en-US", {
          timeZone: mainTz,
          timeZoneName: "longOffset",
        }).formatToParts(new Date());
        const tzn = tzParts.find((p) => p.type === "timeZoneName")?.value ?? "";
        let zoneEast: number | null = null;
        if (tzn === "GMT" || tzn === "UTC") {
          zoneEast = 0;
        } else {
          const m = /GMT([+-])(\d{2}):?(\d{2})?/.exec(tzn);
          if (m) {
            const sign = m[1] === "-" ? -1 : 1;
            zoneEast = sign * (parseInt(m[2] ?? "0", 10) * 60 + parseInt(m[3] ?? "0", 10));
          }
        }
        if (zoneEast !== null && zoneEast !== -mainOff) {
          put("browser", "timezone_internal_incoherent", true);
        }
      }
    } catch {
      /* ignore */
    }
    if (!cspEnforced) put("browser", "csp_bypassed", true);

    // Behavioural layer — only judge once there is enough GENUINE interaction. The behavioural rules
    // are floors (low entropy / no input / too-straight) that a real visitor who simply hasn't moved
    // the mouse yet would trip — scoring the *absence* of input as bot-like is a false positive (the
    // detector demo omits this layer in ?fast for the same reason). Below the floor, emit nothing so
    // those rules resolve MISSING (do not fire). The page asks the visitor to move/type to populate it.
    const BEHAVIOR_MIN_POINTERS = 15;
    if (pts.length >= BEHAVIOR_MIN_POINTERS) {
      put("behavioral", "mouse_entropy", mouseEntropy(pts));
      put("behavioral", "pointer_event_count", pointerEventCount(pts));
      put("behavioral", "mouse_straightness", pathStraightness(pts));
      put("behavioral", "mouse_velocity_cv", velocityCV(pts));
      if (coalescedSupported && ptrMoves >= 20 && coalescedMax <= 1) {
        put("behavioral", "coalesced_events_absent", true);
      }
    }
    // Keystroke cadence only judged with enough keys to be meaningful (else genuinely absent, not a floor).
    if (keys.length >= 4) put("behavioral", "keystroke_entropy", keystrokeEntropy(keys));
    return out;
  }

  return { collect };
}
