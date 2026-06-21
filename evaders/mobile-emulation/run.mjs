// evaders/mobile-emulation/run — a desktop Chromium emulating an Android phone (Playwright Pixel 5 device).
// Tests the mobile surface: a mobile UA + touch + mobile viewport over a DESKTOP engine leaks its real OS.

import { chromium, devices } from "playwright";

const EDGE = process.env.KITSUNE_EDGE ?? "https://edge:8443/";
const DET = process.env.KITSUNE_DETECTOR ?? "http://detector:8080";

// Pixel 5: Android Chrome UA + hasTouch + isMobile + a mobile viewport/deviceScaleFactor. The engine stays
// Chromium (coherent UA-engine, unlike an iPhone descriptor whose Safari UA mismatches Blink), so the residual
// is the cross-layer incoherence a mobile EMULATION on a desktop host cannot hide: the real OS leaks through the
// fonts (br.font_os_vs_ua: Android UA, Linux fonts), the codecs (br.codec_os_incoherent), the software desktop
// GPU (br.webgl_software), and the improbable mobile-UA + desktop-GPU/screen joint (br.fingerprint_improbable).
// NAIVE=1: the header-only mobile spoof — set a phone UA but do NOT emulate the device (no hasTouch /
// isMobile / viewport). This is the common scraper shortcut (a mobile UA override, not full device mode),
// and it leaves navigator.maxTouchPoints at the desktop default 0 → a phone UA on a touch-less client →
// br.mobile_no_touch (the spatial UA<->capability coherence tell). Contrast the full Pixel-5 emulation
// below, which sets hasTouch so maxTouchPoints > 0 and mobile_no_touch correctly stays quiet.
const NAIVE = process.env.NAIVE === "1";
// IOS=1: the iOS naive spoof — an iPhone-Safari UA on a Chromium host (no touch). It self-incriminates three
// ways at once: a Blink-only API under a Safari UA (br.apple_ua_nonwebkit), a Safari UA missing window.
// GestureEvent (br.safari_ua_no_webkit_api), AND a phone UA with maxTouchPoints 0 (br.mobile_no_touch).
const IOS = process.env.IOS === "1";
// FIXED_TOUCH=1: the escalation past br.mobile_no_touch — a spoofer who patched navigator.maxTouchPoints to a
// touch value but left the CSS pointer surface desktop (any-pointer:coarse false). maxTouchPoints>0 keeps
// mobile_no_touch quiet, but the JS-vs-CSS touch disagreement trips br.pointer_touch_incoherent (next rung).
const FIXED_TOUCH = process.env.FIXED_TOUCH === "1";
const ANDROID_MOBILE_UA =
  "Mozilla/5.0 (Linux; Android 14; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36";
const IPHONE_UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";
const UA_ONLY = IOS ? IPHONE_UA : ANDROID_MOBILE_UA;
const device = devices["Pixel 5"];
const browser = await chromium.launch({ headless: true, args: ["--no-sandbox", "--ignore-certificate-errors"] });
const context = await browser.newContext(
  NAIVE || IOS || FIXED_TOUCH ? { userAgent: UA_ONLY, ignoreHTTPSErrors: true } : { ...device, ignoreHTTPSErrors: true },
);
if (FIXED_TOUCH) {
  await context.addInitScript(() => {
    Object.defineProperty(navigator, "maxTouchPoints", { get: () => 5, configurable: true });
  });
}
const page = await context.newPage();
await page.goto(EDGE, { waitUntil: "load" });
await page.waitForTimeout(4000); // margin for the collector's async probes (WebRTC/audio) to POST
const cookie = (await context.cookies()).find((c) => c.name === "ks_sid");
await browser.close();
if (!cookie) {
  console.log("NO_SID");
  process.exit(1);
}
const r = await fetch(`${DET}/verdict/${cookie.value}`);
const mode = IOS
  ? "mobile-ios-naive"
  : FIXED_TOUCH
    ? "mobile-fixed-touch"
    : NAIVE
      ? "mobile-naive-spoof"
      : "mobile-emulation";
console.log("__KS__" + JSON.stringify({ mode, ...(await r.json()) }));
