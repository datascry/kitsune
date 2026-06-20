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
// KS_COHERENT=1: the COHERENT Gecko evader — a real LINUX Firefox UA on the Linux host (oscpu == ua_platform ==
// Linux, TCP-OS == UA-OS == Linux). Unlike coherent-WebKit (Safari ⟹ Mac ⟹ not-Linux), Gecko-on-Linux IS
// OS-coherent (Firefox genuinely runs on Linux servers), so no Mac-on-Linux structural tells. Grounds whether a
// non-Chromium engine on coherent infra approaches EVADES: it speaks no CDP (br.cdp_runtime_enabled should stay
// quiet) and has no HeadlessChrome token, so the question is what Playwright Firefox still leaks (webdriver,
// TLS/h2 vs real Firefox) once the OS axis is coherent.
const COHERENT = process.env.KS_COHERENT === "1";
const LINUX_FF_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0";

// The coherent evader's last convicting tell is br.webdriver_present (Playwright sets navigator.webdriver=true).
// Firefox disables it NATIVELY via the dom.webdriver.enabled pref — navigator.webdriver becomes a real `false`,
// so the tell goes quiet WITHOUT a JS override (which would trip br.webdriver_getter_tampered instead). No CDP,
// no headless token, no anti-detect tool, no xvfb — just stock Playwright Firefox + a coherent UA + one pref.
const launchOpts = COHERENT
  ? { headless: true, args: ["--no-sandbox"], firefoxUserPrefs: { "dom.webdriver.enabled": false } }
  : { headless: true, args: ["--no-sandbox"] };
const browser = await playwright.firefox.launch(launchOpts);
const context = await browser.newContext({ ignoreHTTPSErrors: true, userAgent: COHERENT ? LINUX_FF_UA : WIN_FF_UA });
// KS_HIDEWD=1: the JS-override rung of the webdriver ladder. The dom.webdriver.enabled pref is OVERRIDDEN by
// Playwright's automation (navigator.webdriver stays true), so the only in-sandbox way to hide it is a JS
// redefine — which makes the getter non-native → br.webdriver_getter_tampered. Grounds that the single
// convicting tell on coherent Gecko is robust: native pref ignored, JS-hide trips a sibling tell. Only an
// ENGINE-LEVEL patch (Camoufox) escapes both — locating exactly why Camoufox exists.
if (process.env.KS_HIDEWD === "1") {
  await context.addInitScript(() => {
    Object.defineProperty(Object.getPrototypeOf(navigator), "webdriver", { get: () => false, configurable: true });
  });
}
const page = await context.newPage();

await page.goto(EDGE, { waitUntil: "domcontentloaded", timeout: 30000 });
for (let i = 0; i < 6; i++) await page.mouse.move(120 + i * 40, 130 + i * 20, { steps: 3 });
await page.waitForTimeout(3000); // let the in-page collector POST (1.2s timer + edge round-trip)

const sid = (await context.cookies()).find((c) => c.name === "ks_sid")?.value;
if (!sid) throw new Error("no ks_sid cookie — edge did not mint a session");
const verdict = await (await fetch(`${DETECTOR}/verdict/${sid}`)).json();
console.log("__KS__" + JSON.stringify({ mode: COHERENT ? "firefox-coherent" : "firefox-os-spoof", sid, ...verdict }));

await browser.close();
