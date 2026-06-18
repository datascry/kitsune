// evaders/stealth/run — drive a real Chromium through the edge and read the detector's verdict.
// Modes: naive (automation tells) · STEALTH=1 (patched) · SPOOF_UA=<ua> (Chrome TLS, lying UA).

import { chromium } from "playwright";

const EDGE = process.env.KITSUNE_EDGE || "https://edge:8443/";
const DETECTOR = process.env.KITSUNE_DETECTOR || "http://detector:8080";
const STEALTH = process.env.STEALTH === "1";
const FULL = process.env.FULL === "1"; // contest the whole v0.4.0 browser battery
const SPOOF_UA = process.env.SPOOF_UA; // e.g. a Firefox UA, while the real TLS stays Chrome

const CHROME_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
// Coherent with the container's real Linux platform (no headless token, Linux Client-Hints).
const LINUX_CHROME_UA =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

const userAgent = SPOOF_UA || (FULL ? LINUX_CHROME_UA : STEALTH ? CHROME_UA : undefined);
const evading = STEALTH || FULL || Boolean(SPOOF_UA);
const mode = FULL ? "full-stealth" : SPOOF_UA ? "spoof-ua" : STEALTH ? "stealth" : "naive";

// --ignore-certificate-errors: accept the edge's self-signed cert at the TLS layer (not just the
// navigation layer) so the fingerprinting handshake completes and network signals are captured.
const browser = await chromium.launch({ args: ["--no-sandbox", "--ignore-certificate-errors"] });
const context = await browser.newContext({
  ignoreHTTPSErrors: true,
  ...(userAgent ? { userAgent } : {}),
});
if (FULL) {
  // The full battery: every patch a JS-injection anti-detect would apply. Note webdriver is patched
  // on Navigator.prototype (no own-property tell), and WebGL is given a real GPU string.
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    if (!window.chrome) Object.defineProperty(window, "chrome", { value: { runtime: {} } });
    Object.defineProperty(navigator, "plugins", {
      get: () => [{ name: "Chrome PDF Plugin" }, { name: "Chrome PDF Viewer" }, { name: "Native Client" }],
    });
    const gp = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function (p) {
      if (p === 37445) return "Google Inc. (NVIDIA)";
      if (p === 37446) return "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)";
      return gp.call(this, p);
    };
  });
} else if (evading) {
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
