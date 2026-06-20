// evaders/apify-fp-inject/run — drive Playwright Chromium through the edge with an apify-injected fingerprint.
// Generates a real Linux-Chrome fingerprint (fingerprint-generator) and injects it (fingerprint-injector) to
// spoof navigator/screen/webgl/UA-CH from real captured values — then reports what the live detector convicts.

import { chromium } from "playwright";
import { FingerprintGenerator } from "fingerprint-generator";
import { newInjectedContext } from "fingerprint-injector";

const EDGE = process.env.KITSUNE_EDGE ?? "https://edge:8443/";
const DET = process.env.KITSUNE_DETECTOR ?? "http://detector:8080";

// A real desktop Linux-Chrome fingerprint sampled from apify's corpus: coherent UA string, Sec-CH-UA client
// hints, screen, webgl vendor/renderer and navigator props. The injector wires these into the MAIN realm via
// an init script — which is exactly the gap Kitsune probes: a Web Worker still sees the un-injected headless
// navigator, so the spoof manufactures a worker-vs-main coherence contradiction the un-spoofed browser lacked.
const gen = new FingerprintGenerator({ browsers: ["chrome"], operatingSystems: ["linux"], devices: ["desktop"] });
const out = gen.getFingerprint();

// KS_TRACE=1: also replay ONE byte-identical recorded pointer trajectory (synthetic mousemove events with
// exact clientX/clientY). Run as a fleet, this models the botright/multilogin pattern — RANDOMISE the
// fingerprint per instance (fingerprint-generator samples a fresh one each run → distinct fp_hash) yet REUSE
// one canned "humanised" path → a shared trace_hash. The fp-randomisation defeats fp_collision, but the shared
// trace is what coordination._trace_collision convicts: two real users never trace the identical path.
const TRACE = process.env.KS_TRACE === "1";

const browser = await chromium.launch({ headless: true, args: ["--no-sandbox", "--ignore-certificate-errors"] });
const context = await newInjectedContext(browser, { fingerprint: out, newContextOptions: { ignoreHTTPSErrors: true } });
const page = await context.newPage();
await page.goto(EDGE, { waitUntil: "load" });
if (TRACE) {
  // Exact-dispatch (not page.mouse.move, which the browser coalesces/perturbs run-to-run) — the only way to
  // reproduce a byte-identical trace. Same recorded path as the stealth REPLAY_TRACE fleet (>=12 points).
  await page.evaluate(() => {
    const path = [
      [120, 140], [168, 158], [216, 152], [264, 188], [312, 176], [360, 214], [408, 198],
      [456, 236], [504, 220], [552, 262], [600, 248], [648, 286], [612, 322], [540, 308],
      [468, 344], [396, 330], [324, 366],
    ];
    for (const [x, y] of path) {
      window.dispatchEvent(new MouseEvent("mousemove", { clientX: x, clientY: y, bubbles: true }));
    }
  });
}
await page.waitForTimeout(4000); // margin for the collector's async probes (WebRTC/audio/worker) to POST
const cookie = (await context.cookies()).find((c) => c.name === "ks_sid");
await browser.close();
if (!cookie) {
  console.log("NO_SID");
  process.exit(1);
}
const r = await fetch(`${DET}/verdict/${cookie.value}`);
console.log("__KS__" + JSON.stringify({ mode: TRACE ? "apify-fp-inject-trace" : "apify-fp-inject", ...(await r.json()) }));
