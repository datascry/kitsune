// evaders/stealth/run — drive a real Chromium through the edge and read the detector's verdict.
// MODE naive = vanilla automation (webdriver/headless tells); STEALTH=1 patches webdriver + UA.

import { chromium } from "playwright";

const EDGE = process.env.KITSUNE_EDGE || "https://edge:8443/";
const DETECTOR = process.env.KITSUNE_DETECTOR || "http://detector:8080";
const STEALTH = process.env.STEALTH === "1";

// A real Windows Chrome UA used in stealth mode (note: Client-Hints are NOT spoofed — the detector
// is meant to catch that incoherence).
const CHROME_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

// --ignore-certificate-errors: accept the edge's self-signed cert at the TLS layer (not just the
// navigation layer) so the fingerprinting handshake completes and network signals are captured.
const browser = await chromium.launch({ args: ["--no-sandbox", "--ignore-certificate-errors"] });
const context = await browser.newContext({
  ignoreHTTPSErrors: true,
  ...(STEALTH ? { userAgent: CHROME_UA } : {}),
});
if (STEALTH) {
  await context.addInitScript(() => {
    Object.defineProperty(navigator, "webdriver", { get: () => false });
  });
}

const page = await context.newPage();
await page.goto(EDGE, { waitUntil: "load" });
for (let i = 0; i < 24; i++) {
  await page.mouse.move(100 + i * 7, 120 + Math.sin(i / 2) * 50);
}
await page.waitForTimeout(3500); // let the in-page collector post its signals

const ks = (await context.cookies()).find((c) => c.name === "ks_sid");
if (!ks) {
  console.error("no ks_sid cookie — pipeline not wired");
  process.exit(2);
}
const verdict = await (await fetch(`${DETECTOR}/verdict/${ks.value}`)).json();
console.log(JSON.stringify({ mode: STEALTH ? "stealth" : "naive", ...verdict }, null, 2));
await browser.close();
