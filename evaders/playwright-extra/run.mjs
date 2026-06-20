// evaders/playwright-extra/run — drive playwright-extra + puppeteer-extra-plugin-stealth through the edge.
// The ubiquitous ~17-evasion JS-injection stealth baseline; reports which tells its Proxy-based spoofs evade.

import { chromium } from "playwright-extra";
import StealthPlugin from "puppeteer-extra-plugin-stealth";

const EDGE = process.env.KITSUNE_EDGE ?? "https://edge:8443/";
const DET = process.env.KITSUNE_DETECTOR ?? "http://detector:8080";

// The stealth plugin applies its evasions via evaluateOnNewDocument: webgl.vendor uses replaceWithProxy
// (Proxy-over-native → preserves native invariants + [native code], defeating the artifact layer like apify),
// adds chrome.runtime/app/loadTimes, hides navigator.webdriver, mocks plugins/codecs/permissions. It patches
// only JS, NOT the CDP transport — so the question this grounds is whether br.cdp_runtime_enabled still fires.
chromium.use(StealthPlugin());

const browser = await chromium.launch({ headless: true, args: ["--no-sandbox", "--ignore-certificate-errors"] });
const context = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await context.newPage();
await page.goto(EDGE, { waitUntil: "load" });
await page.waitForTimeout(4000); // margin for the collector's async probes (WebRTC/audio/worker) to POST
const cookie = (await context.cookies()).find((c) => c.name === "ks_sid");
await browser.close();
if (!cookie) {
  console.log("NO_SID");
  process.exit(1);
}
const r = await fetch(`${DET}/verdict/${cookie.value}`);
console.log("__KS__" + JSON.stringify({ mode: "playwright-extra", ...(await r.json()) }));
