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
const ANDROID_MOBILE_UA =
  "Mozilla/5.0 (Linux; Android 14; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36";
const device = devices["Pixel 5"];
const browser = await chromium.launch({ headless: true, args: ["--no-sandbox", "--ignore-certificate-errors"] });
const context = await browser.newContext(
  NAIVE ? { userAgent: ANDROID_MOBILE_UA, ignoreHTTPSErrors: true } : { ...device, ignoreHTTPSErrors: true },
);
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
console.log("__KS__" + JSON.stringify({ mode: NAIVE ? "mobile-naive-spoof" : "mobile-emulation", ...(await r.json()) }));
