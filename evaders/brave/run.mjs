// evaders/brave/run — drive Brave (farbling browser) through the edge and read the verdict.
// Tests the canvas/audio farbling philosophy: per-session readback noise vs coherent spoofing.

import { chromium } from "playwright";

const EDGE = process.env.KITSUNE_EDGE || "https://edge:8443/";
const DETECTOR = process.env.KITSUNE_DETECTOR || "http://detector:8080";

const browser = await chromium.launch({
  executablePath: "/usr/bin/brave-browser",
  args: ["--no-sandbox", "--ignore-certificate-errors"],
});
const context = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await context.newPage();
await page.goto(EDGE, { waitUntil: "load" });
await page.waitForTimeout(2500);
const ks = (await context.cookies()).find((c) => c.name === "ks_sid");
await browser.close();
if (!ks) {
  console.error("no ks_sid cookie");
  process.exit(2);
}
const verdict = await (await fetch(`${DETECTOR}/verdict/${ks.value}`)).json();
console.log("__KS__" + JSON.stringify({ mode: "brave", ...verdict }));
