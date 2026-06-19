// collector/livepage/predict — predict the REAL engine/browser/form-factor from feature detection.
// Independent of the (spoofable) UA string, so the page shows what you actually are AND can apply each
// detection on a per-browser basis — a rule that is meaningless for your browser must not count as a tell.

export type Engine = "blink" | "gecko" | "webkit" | "unknown";
export type FormFactor = "desktop" | "mobile" | "unknown";

export interface Prediction {
  engine: Engine;
  browser: string; // Chrome | Edge | Brave | Opera | Samsung Internet | Firefox | Safari | …
  os: string; // Windows | macOS | Linux | Android | iOS | unknown
  formFactor: FormFactor;
  confidence: number; // 0..1 — how strongly the features pin the engine
  evidence: string[]; // the feature checks that fired
}

const has = (k: string): boolean => k in window;

/** Engine from JS/CSS feature surface — the part a UA string cannot fake without the real APIs. */
function detectEngine(ev: string[]): { engine: Engine; confidence: number } {
  // Gecko: Firefox-only CSS + APIs.
  const gecko =
    CSS.supports("-moz-appearance", "none") ||
    has("InstallTrigger") ||
    has("mozInnerScreenX") ||
    typeof (navigator as { buildID?: string }).buildID === "string";
  // WebKit (Safari): WebKit-only APIs that Blink dropped/never had.
  const webkit =
    (has("GestureEvent") && !has("chrome")) ||
    (CSS.supports("-webkit-touch-callout", "none") && !has("chrome") && !gecko);
  // Blink (Chromium family): the chrome object + UA-CH, neither present in Gecko/WebKit.
  const blink =
    has("chrome") || "userAgentData" in navigator || CSS.supports("-webkit-app-region", "drag");

  if (gecko && !blink) {
    ev.push("CSS -moz-appearance / mozInnerScreenX / buildID");
    return { engine: "gecko", confidence: 0.95 };
  }
  if (blink && !gecko) {
    ev.push(has("chrome") ? "window.chrome present" : "navigator.userAgentData present");
    return { engine: "blink", confidence: 0.95 };
  }
  if (webkit) {
    ev.push("GestureEvent / -webkit-touch-callout, no chrome object");
    return { engine: "webkit", confidence: 0.9 };
  }
  ev.push("no decisive engine feature");
  return { engine: "unknown", confidence: 0.3 };
}

/** The resistFingerprinting signature shared by Tor Browser, Mullvad Browser, and RFP-Firefox: the
 * timezone is forced to UTC, the content window is letterboxed to 200×100 multiples, and
 * hardwareConcurrency is clamped to ≤2. Each trait alone is common (a UK user, a round window, a 2-core
 * VM); the CONJUNCTION is the RFP tell — so all three are required, matching the detector's br.rfp_browser.
 * Tor vs Mullvad is NOT separable here: they share an anonymity set by design and are identical at the JS
 * layer; only the network layer (a Tor exit-IP) tells them apart. */
function rfpGecko(ev: string[]): boolean {
  try {
    let tz = "";
    try {
      tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
    } catch {
      /* intl unavailable */
    }
    const utc = tz === "UTC";
    const letterboxed =
      window.innerWidth > 0 && window.innerWidth % 200 === 0 && window.innerHeight % 100 === 0;
    const lowCores = (navigator.hardwareConcurrency || 99) <= 2;
    if (utc && letterboxed && lowCores) {
      ev.push("RFP signature: UTC timezone + letterboxed window + ≤2 cores");
      ev.push(
        "Tor vs Mullvad is not JS-separable (shared anonymity set) — the exit IP tells them apart",
      );
      return true;
    }
  } catch {
    /* defensive: never block the prediction */
  }
  return false;
}

/** Specific browser within an engine, from vendor-specific globals (not the UA), refined by OS/form. */
function detectBrowser(engine: Engine, os: string, form: FormFactor, ev: string[]): string {
  // iOS: Apple forbids non-WebKit engines, so Safari, Chrome (CriOS), Firefox (FxiOS), Brave, DuckDuckGo,
  // and Onion Browser all run the SAME system WebKit — the engine literally cannot tell them apart. Honest.
  if (os === "iOS") {
    ev.push(
      "iOS: all browsers (Safari/Chrome/Firefox/Brave/DuckDuckGo/Onion) share the system WebKit — not JS-separable by engine",
    );
    return "iOS browser (WebKit)";
  }
  if (engine === "gecko") {
    if (rfpGecko(ev)) {
      // Android Tor Browser / Mull and desktop Tor / Mullvad Browser are the RFP-Gecko privacy family.
      return form === "mobile"
        ? "Tor Browser / Mull (Android, RFP-Gecko)"
        : "Tor / Mullvad Browser";
    }
    if (form === "mobile") {
      ev.push("Gecko on Android = GeckoView family — Firefox / Focus / Fennec share the engine");
      return "Firefox / GeckoView (Android)";
    }
    return "Firefox";
  }
  if (engine === "webkit") return "Safari"; // non-iOS WebKit = desktop Safari (macOS)
  if (engine === "blink") {
    const mob = (name: string): string => (form === "mobile" ? `${name} (Android)` : name);
    if (has("opr") || has("opera")) {
      ev.push("window.opr (Opera)");
      return mob("Opera");
    }
    if ("brave" in navigator) {
      ev.push("navigator.brave (Brave)");
      return mob("Brave");
    }
    const brands =
      (navigator as { userAgentData?: { brands?: { brand: string }[] } }).userAgentData?.brands ??
      [];
    const brand = brands.map((b) => b.brand).join(" ");
    if (/Edg/i.test(brand)) {
      ev.push("UA-CH brand: Edge");
      return mob("Edge");
    }
    if (/Samsung/i.test(brand)) {
      ev.push("UA-CH brand: Samsung Internet");
      return "Samsung Internet"; // Android-only by nature
    }
    if (/Google Chrome/i.test(brand)) {
      ev.push("UA-CH brand: Google Chrome");
      return mob("Chrome");
    }
    // Blink without a vendor tell: Vivaldi, Yandex, UC, DuckDuckGo-Android et al. suppress their brand, so
    // name the family rather than guess a specific browser we cannot ground from features.
    ev.push("Chromium engine, no vendor-specific global or UA-CH brand");
    return mob("Chromium");
  }
  return "unknown";
}

/** OS + form factor. navigator.platform / maxTouchPoints are harder to spoof coherently than the UA. */
function detectOsForm(ev: string[]): { os: string; formFactor: FormFactor } {
  const plat = (navigator.platform || "").toString();
  const touch = navigator.maxTouchPoints > 0 || has("ontouchstart");
  const ua = navigator.userAgent;
  let os = "unknown";
  let form: FormFactor = "unknown";
  // iOS first: iPhone/iPad platform, or a touch Mac (iPad masquerading as Mac).
  if (/iPhone|iPad|iPod/.test(plat) || (plat === "MacIntel" && navigator.maxTouchPoints > 1)) {
    os = "iOS";
    form = "mobile";
    ev.push("iOS platform / touch-Mac (iPad)");
  } else if (/Mac/i.test(plat)) {
    os = "macOS";
    form = "desktop";
  } else if (/Win/i.test(plat)) {
    os = "Windows";
    form = "desktop";
  } else if (/Linux|Android|X11/i.test(plat)) {
    // navigator.platform reports Linux on Android too — touch + small screen disambiguates.
    if (touch && Math.min(screen.width, screen.height) <= 600) {
      os = "Android";
      form = "mobile";
      ev.push("Linux platform + touch + small screen → Android");
    } else if (/Android/i.test(ua)) {
      os = "Android";
      form = "mobile";
    } else {
      os = "Linux";
      form = "desktop";
    }
  }
  return { os, formFactor: form };
}

export function predict(): Prediction {
  const ev: string[] = [];
  const { engine, confidence } = detectEngine(ev);
  const { os, formFactor } = detectOsForm(ev);
  const browser = detectBrowser(engine, os, formFactor, ev);
  return { engine, browser, os, formFactor, confidence, evidence: ev };
}

/** What the (spoofable) User-Agent string CLAIMS — to diff against the feature prediction. */
export function uaClaimed(): { engine: Engine; os: string } {
  const ua = navigator.userAgent;
  let engine: Engine = "unknown";
  if (/Firefox\//.test(ua)) engine = "gecko";
  else if (/Edg\/|OPR\/|Chrome\//.test(ua)) engine = "blink";
  else if (/Version\/.*Safari\//.test(ua)) engine = "webkit";
  let os = "unknown";
  if (/Android/.test(ua)) os = "Android";
  else if (/iPhone|iPad|iPod/.test(ua)) os = "iOS";
  else if (/Windows/.test(ua)) os = "Windows";
  else if (/Macintosh|Mac OS X/.test(ua)) os = "macOS";
  else if (/Linux|X11/.test(ua)) os = "Linux";
  return { engine, os };
}

export interface Coherence {
  match: boolean;
  claimedEngine: Engine;
  claimedOs: string;
  reason: string;
}

/** The thesis, up front: does the feature-detected engine/OS agree with what the UA claims? A Gecko
 * engine under a Chrome UA, or a Linux host under a Windows UA, is a spoof a real browser never produces. */
export function coherence(pred: Prediction): Coherence {
  const c = uaClaimed();
  const engineOk = pred.engine === "unknown" || c.engine === "unknown" || pred.engine === c.engine;
  const osOk = pred.os === "unknown" || c.os === "unknown" || pred.os === c.os;
  const match = engineOk && osOk;
  const reason = match
    ? "feature prediction agrees with the User-Agent"
    : !engineOk
      ? `features detect ${pred.engine}, but the UA claims ${c.engine}`
      : `features detect ${pred.os}, but the UA claims ${c.os}`;
  return { match, claimedEngine: c.engine, claimedOs: c.os, reason };
}

// Per-browser applicability. A detection that is meaningless for the predicted browser/form-factor must
// not count as a tell — that is what lowers false positives. Each entry maps a rule id to a reason it does
// NOT apply for a given prediction; if `notApplicable` returns a reason, the rule is shown but excluded
// from the verdict.
//
// The load-bearing case: the platform-coherence rules compare the UA's OS to navigator.platform / WebGL /
// oscpu. On mobile that is a legitimate mismatch — Android's navigator.platform is "Linux …" and iOS Safari
// reports its own quirks — so a desktop-oriented platform-coherence rule false-fires on real mobile (the
// Intoli real-traffic source measured this at 73% for navplatform_vs_ua). Marked N/A on mobile.
const PLATFORM_COHERENCE = new Set(["br.navplatform_vs_ua", "br.webgl_os_vs_ua", "br.oscpu_vs_ua"]);
// window.chrome / navigator.connection / deviceMemory are Chromium-only; their absence is a tell only for a
// Chromium browser, never for Firefox/Safari (where it is expected).
const CHROMIUM_ONLY = new Set([
  "br.no_chrome_object",
  "br.chrome_runtime_missing",
  "br.no_connection",
  "br.no_devicememory",
]);
// Brave farbles the canvas and audio readback BY DESIGN (its default "Shields" privacy feature), so a real
// Brave user trips canvas_noise / audio_noise — but Brave is a legitimate human browser (~70M users), not a
// bot. These farbling artifacts are EXPECTED when the browser is positively identified as Brave (the
// definitive navigator.brave global, which detectBrowser reads). A non-Brave browser that farbles — a
// Chrome-claiming anti-detect tool with NO navigator.brave — has no such excuse and still convicts.
const BRAVE_FARBLING = new Set(["br.canvas_noise", "br.audio_noise"]);

export function notApplicable(ruleId: string, pred: Prediction): string | null {
  if (PLATFORM_COHERENCE.has(ruleId) && pred.formFactor === "mobile") {
    return `${pred.os} reports a Linux/host platform that legitimately differs from its UA — expected on mobile`;
  }
  if (CHROMIUM_ONLY.has(ruleId) && pred.engine !== "blink") {
    return `a Chromium-only capability — its absence is expected on ${pred.browser}`;
  }
  if (BRAVE_FARBLING.has(ruleId) && pred.browser.startsWith("Brave")) {
    return "Brave farbles canvas/audio readback by design (its Shields privacy feature) — expected, not a bot signature";
  }
  // Firefox (and every Gecko browser: Tor, Mullvad, Camoufox) generalises the WebGL renderer string
  // ("…, or similar" / "llvmpipe, or similar") by default as a fingerprinting-resistance feature, so a real
  // Firefox trips br.webgl_renderer_artifact — mirrors detector.applicability (grounded on a live FF137).
  if (ruleId === "br.webgl_renderer_artifact" && pred.engine === "gecko") {
    return "Firefox generalises the WebGL renderer string ('…, or similar') by design — a privacy feature, not a spoof";
  }
  return null;
}
