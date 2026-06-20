// evaders/playwright-extra/run — drive playwright-extra + puppeteer-extra-plugin-stealth through the edge.
// The ubiquitous ~17-evasion JS-injection stealth baseline; reports which tells its Proxy-based spoofs evade.

import { chromium } from "playwright-extra";
import StealthPlugin from "puppeteer-extra-plugin-stealth";
import UserAgentOverride from "puppeteer-extra-plugin-stealth/evasions/user-agent-override/index.js";

const EDGE = process.env.KITSUNE_EDGE ?? "https://edge:8443/";
const DET = process.env.KITSUNE_DETECTOR ?? "http://detector:8080";

// The stealth plugin applies its evasions via evaluateOnNewDocument: webgl.vendor uses replaceWithProxy
// (Proxy-over-native → preserves native invariants + [native code], defeating the artifact layer like apify),
// adds chrome.runtime/app/loadTimes, hides navigator.webdriver, mocks plugins/codecs/permissions. It patches
// only JS, NOT the CDP transport — so br.cdp_runtime_enabled still fires.
//
// DEFAULT-CONFIG SELF-DEFEAT (white-boxed): user-agent-override defaults to `maskLinux: true`, which on a Linux
// host REWRITES the UA's platform to `Windows NT 10.0` while the TCP/IP stack stays Linux → a guaranteed
// net.tcp_os_vs_ua on the exact hosts scrapers run (the plugin's own README admits unmasking "makes detection
// very easy", but masking creates a WORSE cross-layer tell). KS_COHERENT_UA=1 hardens it: replace the evasion
// with maskLinux:false so the UA stays coherently Linux → tcp_os_vs_ua goes quiet, leaving the structural
// catches the JS-injection approach cannot fix (cdp_runtime_enabled + main-realm-only worker_divergence).
const COHERENT_UA = process.env.KS_COHERENT_UA === "1";
const stealth = StealthPlugin();
if (COHERENT_UA) {
  stealth.enabledEvasions.delete("user-agent-override");
}
chromium.use(stealth);
if (COHERENT_UA) {
  chromium.use(UserAgentOverride({ maskLinux: false }));
}

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
console.log("__KS__" + JSON.stringify({ mode: COHERENT_UA ? "playwright-extra-coherent" : "playwright-extra", ...(await r.json()) }));
