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
const device = devices["Pixel 5"];
const browser = await chromium.launch({ headless: true, args: ["--no-sandbox", "--ignore-certificate-errors"] });
const context = await browser.newContext({ ...device, ignoreHTTPSErrors: true });
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
console.log("__KS__" + JSON.stringify({ mode: "mobile-emulation", ...(await r.json()) }));
