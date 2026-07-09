// harness/tools/captcha_probe_run — run the captcha signal-probe against a page and print its functional spec.
// Injects captcha_probe.js via addInitScript (BEFORE page scripts), drives a little pointer motion, dumps the report.

import playwright from "playwright";

const ENGINE = process.env.ENGINE || "chromium";
const PAGE = process.env.PROBE_URL || "https://edge:8443/";
const PROBE = process.env.PROBE_PATH || "/probe/captcha_probe.js";

const browser = await playwright[ENGINE].launch({
  headless: true,
  args: ENGINE === "chromium" ? ["--ignore-certificate-errors"] : [],
});
const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
await ctx.addInitScript({ path: PROBE }); // runs in every frame BEFORE the page's own scripts
const page = await ctx.newPage();
await page.goto(PAGE, { waitUntil: "domcontentloaded", timeout: 30000 });
// real pointer motion so any behavioural listeners actually fire
for (let i = 0; i < 8; i++) await page.mouse.move(80 + i * 40, 100 + i * 22, { steps: 3 });
await page.waitForTimeout(3000); // let the collector run + POST
const rep = await page.evaluate(() => (window.__KS_PROBE__ ? window.__KS_PROBE__.report() : null));
console.log("__PROBE__" + JSON.stringify(rep));
await browser.close();
