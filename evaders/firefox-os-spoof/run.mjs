// evaders/firefox-os-spoof/run — a Firefox bot that fakes its UA OS but forgets navigator.oscpu.
// Playwright Firefox (real oscpu="Linux x86_64") under a Windows UA → oscpu_os≠ua_platform → br.oscpu_vs_ua.

// The Firefox analog of the Chromium UA-OS spoofers: a naive geo/OS spoof overrides navigator.userAgent to
// claim Windows but leaves navigator.oscpu (a Firefox-ONLY surface) at its real "Linux x86_64" value. The
// stealth fleet is Chromium and has no oscpu, so this is the only evader that can exercise br.oscpu_vs_ua.
// Grounded FP-safe: a real Firefox's oscpu matches its UA OS (the headful Firefox capture: oscpu_os==ua_platform).

import playwright from "playwright";

const EDGE = process.env.KITSUNE_EDGE || "https://edge:8443/";
const DETECTOR = process.env.KITSUNE_DETECTOR || "http://detector:8080";
// A Windows Firefox UA while the engine runs on the Linux host — navigator.oscpu stays "Linux x86_64".
const WIN_FF_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0";

const browser = await playwright.firefox.launch({ headless: true, args: ["--no-sandbox"] });
const context = await browser.newContext({ ignoreHTTPSErrors: true, userAgent: WIN_FF_UA });
const page = await context.newPage();

await page.goto(EDGE, { waitUntil: "domcontentloaded", timeout: 30000 });
for (let i = 0; i < 6; i++) await page.mouse.move(120 + i * 40, 130 + i * 20, { steps: 3 });
await page.waitForTimeout(3000); // let the in-page collector POST (1.2s timer + edge round-trip)

const sid = (await context.cookies()).find((c) => c.name === "ks_sid")?.value;
if (!sid) throw new Error("no ks_sid cookie — edge did not mint a session");
const verdict = await (await fetch(`${DETECTOR}/verdict/${sid}`)).json();
console.log("__KS__" + JSON.stringify({ mode: "firefox-os-spoof", sid, ...verdict }));

await browser.close();
