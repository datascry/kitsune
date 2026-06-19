// harness/tools/headful_capture — capture a REAL HEADFUL browser's signals through the live edge+detector.
// No automation spoofs: a clean Chromium/Firefox/WebKit (ENGINE=) drives the genuine collector → Tier-2 truth.

// This is the second, independent calibration source the standing constraint asks for: a real headful
// browser (via xvfb), driven only enough to navigate, whose FINGERPRINT signals are genuine ground truth
// for the coherence/artifact rules. It runs the same in-page collector evaders use, so the captured
// session is exactly what a real browser emits — not a generated (browserforge) or mapped (Intoli) proxy.

import playwright from "playwright";

const ENGINE = process.env.ENGINE || "chromium"; // chromium | firefox | webkit
const EDGE = process.env.KITSUNE_EDGE || "https://edge:8443/";
const DETECTOR = process.env.KITSUNE_DETECTOR || "http://detector:8080";

const launcher = playwright[ENGINE];
if (!launcher) throw new Error(`unknown ENGINE ${ENGINE}`);

// Headful (headless:false) — runs under xvfb. The only chromium arg is cert-ignore for the edge's
// self-signed TLS; NO stealth/spoof args, so this is a stock browser. ignoreHTTPSErrors covers ff/webkit.
const args = ENGINE === "chromium" ? ["--ignore-certificate-errors"] : [];
const browser = await launcher.launch({ headless: false, args });
const context = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await context.newPage();

await page.goto(EDGE, { waitUntil: "load", timeout: 30000 });
// Move the mouse a little so the behavioral collector has real (xvfb-dispatched) pointer samples.
for (let i = 0; i < 8; i++) await page.mouse.move(100 + i * 30, 120 + i * 17, { steps: 4 });
await page.waitForTimeout(2500); // let the in-page collector POST its signals to /ingest

const cookies = await context.cookies();
const sid = cookies.find((c) => c.name === "ks_sid")?.value;
if (!sid) throw new Error("no ks_sid cookie — edge did not mint a session");

const session = await (await fetch(`${DETECTOR}/session/${sid}`)).json();
const verdict = await (await fetch(`${DETECTOR}/verdict/${sid}`)).json();
console.log("__CAP__" + JSON.stringify({ engine: ENGINE, sid, session, verdict }));

await browser.close();
