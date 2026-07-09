// harness/tools/captcha_probe_run — run the captcha signal-probe against a page and print its functional spec.
// Injects captcha_probe.js via addInitScript (BEFORE page scripts, in EVERY frame), then merges the per-frame
// reports — so an iframe'd widget (Turnstile/Arkose isolate theirs) is captured, not just the top-frame bridge.

import playwright from "playwright";

const ENGINE = process.env.ENGINE || "chromium";
const PAGE = process.env.PROBE_URL || "https://edge:8443/";
const PROBE = process.env.PROBE_PATH || "/probe/captcha_probe.js";
const CLICK = process.env.CLICK_SELECTOR; // optional: click to spawn an interaction-gated widget (Arkose/GeeTest)

// interaction-gated widgets only load their real (challenge) frame after a click — trigger it, then let it settle
export async function maybeClick(page) {
  if (!CLICK) return;
  try {
    await page.click(CLICK, { timeout: 5000 });
    await page.waitForTimeout(3000);
  } catch (_) {}
}

const host = (u) => {
  try {
    return new URL(u).host || new URL(u).protocol;
  } catch (_) {
    return String(u).slice(0, 40);
  }
};

// collect window.__KS_PROBE__ from EVERY frame and merge into one spec (signals tagged with the frames they came from)
export async function collectAllFrames(page) {
  const reports = [];
  for (const frame of page.frames()) {
    try {
      const r = await frame.evaluate(() => (window.__KS_PROBE__ ? window.__KS_PROBE__.report() : null));
      if (r) reports.push({ frame: frame.url(), ...r });
    } catch (_) {}
  }
  const sig = new Map();
  const lis = new Map();
  const net = [];
  const frames = [];
  for (const r of reports) {
    frames.push(r.frame);
    for (const s of r.signals || []) {
      const k = s.cat + ":" + s.name;
      let e = sig.get(k);
      if (!e) {
        e = { cat: s.cat, name: s.name, count: 0, firstMs: s.ms, samples: [], frames: new Set() };
        sig.set(k, e);
      }
      e.count += s.count;
      e.firstMs = Math.min(e.firstMs, s.ms);
      e.frames.add(host(r.frame));
      for (const x of s.samples || []) if (e.samples.length < 4 && !e.samples.includes(x)) e.samples.push(x);
    }
    for (const b of r.behavioral || []) {
      let e = lis.get(b.event);
      if (!e) e = lis.set(b.event, { count: 0, firstMs: b.ms }).get(b.event);
      e.count += b.count;
      e.firstMs = Math.min(e.firstMs, b.ms);
    }
    for (const n of r.network || []) net.push({ ...n, frame: host(r.frame) });
  }
  const signals = [...sig.values()]
    .sort((a, b) => a.firstMs - b.firstMs)
    .map((e) => ({ ms: e.firstMs, cat: e.cat, name: e.name, count: e.count, samples: e.samples, frames: [...e.frames] }));
  const behavioral = [...lis.entries()].map(([event, e]) => ({ event, count: e.count, ms: e.firstMs })).sort((a, b) => a.ms - b.ms);
  return { frames: frames.map(host), counts: { signals: signals.length, listeners: behavioral.length, requests: net.length }, signals, behavioral, network: net };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const browser = await playwright[ENGINE].launch({
    headless: true,
    args: ENGINE === "chromium" ? ["--ignore-certificate-errors"] : [],
  });
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  await ctx.addInitScript({ path: PROBE });
  const page = await ctx.newPage();
  await page.goto(PAGE, { waitUntil: "domcontentloaded", timeout: 30000 });
  for (let i = 0; i < 8; i++) await page.mouse.move(80 + i * 40, 100 + i * 22, { steps: 3 });
  await page.waitForTimeout(4500); // let every frame's collector + any worker report land
  await maybeClick(page);
  console.log("__PROBE__" + JSON.stringify(await collectAllFrames(page)));
  await browser.close();
}
