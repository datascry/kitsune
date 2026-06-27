// harness/tools/webgl_caps_spoof — a faithful red-team capture that grounds br.webgl_caps_worker_vs_main.
// Fakes the WebGL renderer in BOTH realms (so br.webgl_worker_vs_main stays quiet) but fakes a limit in the
// MAIN realm only, leaking the Worker's real caps → webgl_caps_worker_divergence fires. The hardened tell.

import playwright from "playwright";

const EDGE = process.env.KITSUNE_EDGE || "https://edge:8443/";
const DETECTOR = process.env.KITSUNE_DETECTOR || "http://detector:8080";

const browser = await playwright.chromium.launch({ headless: false, args: ["--ignore-certificate-errors"] });
const context = await browser.newContext({ ignoreHTTPSErrors: true });

// Models a profile-spoofer that fakes a WebGL capability LIMIT in the MAIN realm (e.g. to claim a higher-end
// GPU's MAX_TEXTURE_SIZE) but leaves the renderer string untouched and never reaches Worker scope. The page's
// renderer therefore still MATCHES the Worker's (br.webgl_worker_vs_main stays quiet), yet the main-realm
// limit no longer matches the Worker's real limit → only the hardened caps comparison catches it. This is the
// case the renderer-string check misses by construction. (addInitScript runs in the page realm, not the
// dedicated Worker, so the Worker reports the genuine GPU — exactly the asymmetry the rule exploits.)
await context.addInitScript(() => {
  const proto = self.WebGLRenderingContext && self.WebGLRenderingContext.prototype;
  if (!proto || !proto.getParameter) return;
  const orig = proto.getParameter;
  proto.getParameter = function (p) {
    if (p === 0x0d33) return 32768; // MAX_TEXTURE_SIZE faked in MAIN only; renderer left real → caps diverge
    return orig.call(this, p);
  };
});

const page = await context.newPage();
await page.goto(EDGE, { waitUntil: "domcontentloaded", timeout: 30000 });
for (let i = 0; i < 8; i++) await page.mouse.move(100 + i * 30, 120 + i * 17, { steps: 4 });
await page.waitForTimeout(2500);

const sid = (await context.cookies()).find((c) => c.name === "ks_sid")?.value;
if (!sid) throw new Error("no ks_sid cookie — edge did not mint a session");
const session = await (await fetch(`${DETECTOR}/session/${sid}`)).json();
const verdict = await (await fetch(`${DETECTOR}/verdict/${sid}`)).json();
console.log("__CAP__" + JSON.stringify({ engine: "chromium-webgl-caps-spoof", sid, session, verdict }));
await browser.close();
