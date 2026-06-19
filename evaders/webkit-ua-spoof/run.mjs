// evaders/webkit-ua-spoof/run — a WebKit-engine bot faking a Chrome UA (TLS engine ≠ claimed browser).
// Playwright WebKit (real WebKit TLS, ja4_browser_hint=safari) under a Chrome UA → net.tls_vs_ua_browser.

// The WebKit analog of the Chromium UA-spoofers: a bot uses the real WebKit engine (so it passes the
// engine-API tells apple_ua_nonwebkit / safari_ua_no_webkit_api) but lies in its UA, claiming Chrome. The
// TLS handshake below the JS layer is WebKit's, which the UA cannot change — ja4_browser_hint=safari vs
// ua_browser=chrome. Grounded FP-safe: a real WebKit with a Safari UA (the headful capture) has
// ja4_browser_hint == ua_browser (safari) and does NOT fire.

import playwright from "playwright";

const EDGE = process.env.KITSUNE_EDGE || "https://edge:8443/";
const DETECTOR = process.env.KITSUNE_DETECTOR || "http://detector:8080";
// A desktop Chrome UA while the engine is WebKit — the TLS/JA4 stays WebKit's.
const CHROME_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

// WebKit rejects chromium args (--no-sandbox); launch bare. ignoreHTTPSErrors accepts the edge's cert.
const browser = await playwright.webkit.launch({ headless: true });
const context = await browser.newContext({ ignoreHTTPSErrors: true, userAgent: CHROME_UA });
const page = await context.newPage();

await page.goto(EDGE, { waitUntil: "domcontentloaded", timeout: 30000 });
for (let i = 0; i < 6; i++) await page.mouse.move(120 + i * 40, 130 + i * 20, { steps: 3 });
await page.waitForTimeout(3000); // let the in-page collector POST (1.2s timer + edge round-trip)

const sid = (await context.cookies()).find((c) => c.name === "ks_sid")?.value;
if (!sid) throw new Error("no ks_sid cookie — edge did not mint a session");
const verdict = await (await fetch(`${DETECTOR}/verdict/${sid}`)).json();
console.log("__KS__" + JSON.stringify({ mode: "webkit-ua-spoof", sid, ...verdict }));

await browser.close();
