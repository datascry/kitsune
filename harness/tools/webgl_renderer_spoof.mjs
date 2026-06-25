// harness/tools/webgl_renderer_spoof — ground G18: a high-end renderer STRING over real (SwiftShader) caps.
// Spoofs UNMASKED_RENDERER in BOTH realms (defeating worker_vs_main) but leaves MAX_TEXTURE_SIZE truthful.

// The source-level anti-detect FORK frontier (CloakBrowser/Wayfern/BotBrowser) patches the WebGL renderer
// STRING consistently across main+worker realms, so br.webgl_worker_vs_main cannot see it. It cannot, however,
// change what the physical backend can do: MAX_TEXTURE_SIZE on the headless SwiftShader backend stays 8192,
// below the 16384 floor every real RTX/Apple-M/Arc exposes. This init-script reproduces exactly that lie:
// getParameter(UNMASKED_RENDERER/VENDOR) returns a forged "RTX 4090" identity; every other parameter (caps)
// passes through untouched. The collector must then emit browser.webgl_renderer_caps_mismatch and convict.

import playwright from "playwright";

const EDGE = process.env.KITSUNE_EDGE || "https://edge:8443/";
const DETECTOR = process.env.KITSUNE_DETECTOR || "http://detector:8080";
const RENDERER = process.env.KS_RENDERER || "ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 (0x00002684) Direct3D11 vs_5_0 ps_5_0, D3D11)";
const VENDOR = process.env.KS_VENDOR || "Google Inc. (NVIDIA)";

// UNMASKED_VENDOR_WEBGL=0x9245, UNMASKED_RENDERER_WEBGL=0x9246. Patch getParameter on BOTH WebGL1+WebGL2
// prototypes (the fork spoofs every realm); all other enums — crucially MAX_TEXTURE_SIZE=0x0D33 — fall through
// to the real native implementation, so the silicon's true capabilities are reported unchanged.
const SPOOF = `(() => {
  const R = ${JSON.stringify(RENDERER)}, V = ${JSON.stringify(VENDOR)};
  const patch = (proto) => {
    if (!proto || !proto.getParameter) return;
    const real = proto.getParameter;
    proto.getParameter = function (p) {
      if (p === 0x9246) return R;
      if (p === 0x9245) return V;
      return real.call(this, p);
    };
  };
  patch(self.WebGLRenderingContext && self.WebGLRenderingContext.prototype);
  patch(self.WebGL2RenderingContext && self.WebGL2RenderingContext.prototype);
})()`;

// Headless Chromium uses the SwiftShader backend (MAX_TEXTURE_SIZE=8192) — the exact below-floor surface
// G18 grounds on — so no xvfb is needed; set HEADFUL=1 to force a real display.
const args = ["--ignore-certificate-errors"];
const browser = await playwright.chromium.launch({ headless: !process.env.HEADFUL, args });
const context = await browser.newContext({ ignoreHTTPSErrors: true });
await context.addInitScript(SPOOF); // runs in every realm (main + worker) before page scripts
const page = await context.newPage();

await page.goto(EDGE, { waitUntil: "domcontentloaded", timeout: 30000 });
for (let i = 0; i < 8; i++) await page.mouse.move(100 + i * 30, 120 + i * 17, { steps: 4 });
await page.waitForTimeout(2500); // let the in-page collector POST its signals to /ingest

const cookies = await context.cookies();
const sid = cookies.find((c) => c.name === "ks_sid")?.value;
if (!sid) throw new Error("no ks_sid cookie — edge did not mint a session");

const session = await (await fetch(`${DETECTOR}/session/${sid}`)).json();
const verdict = await (await fetch(`${DETECTOR}/verdict/${sid}`)).json();
console.log("__CAP__" + JSON.stringify({ sid, session, verdict }));

await browser.close();
