// harness/tools/css_beacon_ground — headful grounding for the S1 CSS⇄JS touch-coherence beacon.
// Loads the exact @font-face @media beacon in real Chromium across touch states; checks CSS==JS (no FP) + spoof.

// Grounds br.css_pointer_vs_js_touch (docs/detection-landscape.md S1). A tiny local server serves a page
// carrying the SAME @font-face @media(any-pointer:coarse) beacon shipped in detector/demo.py; Playwright
// route-intercepts the engine's /b/ fetch to read which media value the rendering engine resolved, and reads
// navigator.maxTouchPoints in-page. The FP claim ("a real browser keeps the CSS channel == the JS channel")
// and the CONVICTS claim ("a JS-only maxTouchPoints spoof cannot move the CSS beacon → they disagree") are
// both checked against a real headful engine — the grounding the synthetic calibration gate cannot do.

import http from "node:http";
import playwright from "playwright";

// The exact beacon CSS shipped in detector/demo.py (kept in sync).
const BEACON_CSS = `
@font-face{font-family:kspt;src:url("/b/any_pointer_coarse/0")}
@media (any-pointer: coarse){@font-face{font-family:kspt;src:url("/b/any_pointer_coarse/1")}}
.ks-beacon{position:absolute;left:-9999px;top:-9999px;font-family:kspt}
`;
const HTML = `<!doctype html><html><head><meta charset="utf-8"><style>${BEACON_CSS}</style></head><body><span class="ks-beacon" aria-hidden="true">.</span></body></html>`;

const server = http.createServer((req, res) => {
  if (req.url.startsWith("/b/")) {
    res.writeHead(204);
    res.end();
    return;
  }
  res.writeHead(200, { "content-type": "text/html" });
  res.end(HTML);
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const url = `http://127.0.0.1:${server.address().port}/`;

const browser = await playwright.chromium.launch({ headless: false, args: ["--no-sandbox"] });

async function run(label, ctxOpts, initScript) {
  const context = await browser.newContext(ctxOpts);
  let beacon = null;
  await context.route("**/b/any_pointer_coarse/**", (route) => {
    beacon = route.request().url().split("/").pop(); // "0" | "1"
    route.fulfill({ status: 204, body: "" });
  });
  const page = await context.newPage();
  if (initScript) await page.addInitScript(initScript);
  await page.goto(url, { waitUntil: "networkidle" });
  await page.waitForTimeout(400);
  const mtp = await page.evaluate(() => navigator.maxTouchPoints || 0);
  await context.close();
  const cssCoarse = beacon === "1";
  const jsTouch = mtp > 0;
  return { label, css_coarse: cssCoarse, js_touch: jsTouch, agree: cssCoarse === jsTouch, beacon, maxTouchPoints: mtp };
}

const results = [];
// FP cases: a REAL browser (with and without touch) must keep CSS == JS (agree → rule stays silent).
results.push(await run("desktop-no-touch", {}, null));
results.push(await run("real-touch", { hasTouch: true, isMobile: true, viewport: { width: 390, height: 844 } }, null));
// CONVICTS case: a JS-only maxTouchPoints spoof cannot move the CSS beacon → disagree (the rule fires).
results.push(
  await run("js-spoof-maxtouch", {}, () => {
    Object.defineProperty(navigator, "maxTouchPoints", { get: () => 5, configurable: true });
  }),
);

await browser.close();
server.close();

for (const r of results) console.log("__GROUND__" + JSON.stringify(r));
const fpOk = results.filter((r) => r.label !== "js-spoof-maxtouch").every((r) => r.agree);
const convicts = results.find((r) => r.label === "js-spoof-maxtouch");
const convictsOk = convicts && !convicts.agree;
console.log(`__VERDICT__ FP-safe(real browsers agree)=${fpOk}  CONVICTS(spoof disagrees)=${convictsOk}`);
process.exit(fpOk && convictsOk ? 0 : 1);
