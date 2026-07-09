// harness/tools/captcha_probe_diff — probe a TARGET page and diff its functional spec against a baseline.
// The baseline defaults to our own collector page; the gap = signals/listeners/endpoints the target uses that we
// don't — i.e. exactly what a vendor-profile must add to reproduce the target's mechanism vendor-neutrally.

import playwright from "playwright";

const ENGINE = process.env.ENGINE || "chromium";
const BASELINE = process.env.BASELINE_URL || "https://edge:8443/"; // our collector = the "what we already cover" side
const TARGET = process.env.TARGET_URL; // the widget/page to characterise (a vendor demo, or a local stand-in)
const PROBE = process.env.PROBE_PATH || "/probe/captcha_probe.js";
if (!TARGET) {
  console.error("set TARGET_URL (the page to probe); BASELINE_URL defaults to our collector");
  process.exit(2);
}

const pathOf = (u) => {
  try {
    return new URL(u, "http://x").pathname;
  } catch (_) {
    return String(u);
  }
};

async function probe(browser, url) {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  await ctx.addInitScript({ path: PROBE });
  const page = await ctx.newPage();
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30000 }).catch(() => {});
  for (let i = 0; i < 8; i++) await page.mouse.move(80 + i * 40, 100 + i * 22, { steps: 3 });
  await page.waitForTimeout(3000);
  const rep = await page.evaluate(() => (window.__KS_PROBE__ ? window.__KS_PROBE__.report() : { signals: [], behavioral: [], network: [] }));
  await ctx.close();
  return rep;
}

const browser = await playwright[ENGINE].launch({
  headless: true,
  args: ENGINE === "chromium" ? ["--ignore-certificate-errors"] : [],
});
const base = await probe(browser, BASELINE);
const tgt = await probe(browser, TARGET);
await browser.close();

const baseSig = new Set(base.signals.map((s) => s.cat + ":" + s.name));
const baseLis = new Set(base.behavioral.map((b) => b.event));
const basePath = new Set(base.network.map((n) => pathOf(n.url)));

const gap = {
  baseline: BASELINE,
  target: TARGET,
  signals_target_only: tgt.signals.filter((s) => !baseSig.has(s.cat + ":" + s.name)).map((s) => ({ cat: s.cat, name: s.name, samples: s.samples })),
  listeners_target_only: tgt.behavioral.filter((b) => !baseLis.has(b.event)).map((b) => b.event),
  endpoints_target_only: tgt.network.filter((n) => !basePath.has(pathOf(n.url))).map((n) => ({ method: n.method, url: n.url, body: n.body })),
  covered: { signals: [...baseSig].length, listeners: [...baseLis].length },
};
console.log("__DIFF__" + JSON.stringify(gap));
