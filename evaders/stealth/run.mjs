// evaders/stealth/run — drive a real Chromium through the edge and read the detector's verdict.
// Modes: naive (automation tells) · STEALTH=1 (patched) · SPOOF_UA=<ua> (Chrome TLS, lying UA).

import { chromium } from "playwright";

const EDGE = process.env.KITSUNE_EDGE || "https://edge:8443/";
const DETECTOR = process.env.KITSUNE_DETECTOR || "http://detector:8080";
const STEALTH = process.env.STEALTH === "1";
const SPOOF_UA = process.env.SPOOF_UA; // e.g. a Firefox UA, while the real TLS stays Chrome

const CHROME_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

// SPOOF_UA wins: present a lying UA on top of Chromium's real Chrome TLS to trigger the network<->
// browser coherence check. STEALTH presents a coherent Chrome UA + patched webdriver.
const userAgent = SPOOF_UA || (STEALTH ? CHROME_UA : undefined);
const evading = STEALTH || Boolean(SPOOF_UA);
const mode = SPOOF_UA ? "spoof-ua" : STEALTH ? "stealth" : "naive";

// --ignore-certificate-errors: accept the edge's self-signed cert at the TLS layer (not just the
// navigation layer) so the fingerprinting handshake completes and network signals are captured.
const browser = await chromium.launch({ args: ["--no-sandbox", "--ignore-certificate-errors"] });
const context = await browser.newContext({
  ignoreHTTPSErrors: true,
  ...(userAgent ? { userAgent } : {}),
});
if (evading) {
  await context.addInitScript(() => {
    Object.defineProperty(navigator, "webdriver", { get: () => false });
  });
}

const page = await context.newPage();
await page.goto(EDGE, { waitUntil: "load" });
for (let i = 0; i < 24; i++) {
  await page.mouse.move(100 + i * 7, 120 + Math.sin(i / 2) * 50);
}
await page.waitForTimeout(2000); // let the in-page collector post its signals

const ks = (await context.cookies()).find((c) => c.name === "ks_sid");
if (!ks) {
  console.error("no ks_sid cookie — pipeline not wired");
  process.exit(2);
}
const verdict = await (await fetch(`${DETECTOR}/verdict/${ks.value}`)).json();
console.log(JSON.stringify({ mode, ...verdict }, null, 2));
await browser.close();
