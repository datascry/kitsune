// harness/tools/mobile_no_touch_capture — a faithful red-team capture that grounds br.mobile_no_touch.
// A desktop browser spoofing a MOBILE UA but leaving maxTouchPoints=0 — a real phone always reports touch.

import playwright from "playwright";

const EDGE = process.env.KITSUNE_EDGE || "https://edge:8443/";
const DETECTOR = process.env.KITSUNE_DETECTOR || "http://detector:8080";

// A real iPhone Safari UA on a stock DESKTOP Chromium: the UA claims mobile, but maxTouchPoints stays 0
// (no hasTouch). A genuine iPhone always reports touch support — only a desktop faker forgets it.
const IPHONE_UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";

const browser = await playwright.chromium.launch({ headless: false, args: ["--ignore-certificate-errors"] });
const context = await browser.newContext({ ignoreHTTPSErrors: true, userAgent: IPHONE_UA }); // NO hasTouch → maxTouchPoints 0
const page = await context.newPage();
await page.goto(EDGE, { waitUntil: "domcontentloaded", timeout: 30000 });
for (let i = 0; i < 8; i++) await page.mouse.move(100 + i * 30, 120 + i * 17, { steps: 4 });
await page.waitForTimeout(2500);

const sid = (await context.cookies()).find((c) => c.name === "ks_sid")?.value;
if (!sid) throw new Error("no ks_sid cookie — edge did not mint a session");
const session = await (await fetch(`${DETECTOR}/session/${sid}`)).json();
const verdict = await (await fetch(`${DETECTOR}/verdict/${sid}`)).json();
console.log("__CAP__" + JSON.stringify({ engine: "chromium-mobile-no-touch", sid, session, verdict }));
await browser.close();
