// harness/tools/captcha_probe_diff — probe a TARGET page and diff its functional spec against a baseline.
// Merges per-frame reports (so iframe'd widgets are captured), then the gap = the signals / listeners / endpoints
// the target uses that the baseline (our collector) does not — i.e. what a vendor-profile must add to reproduce it.

import playwright from "playwright";

import { collectAllFrames, maybeClick } from "./captcha_probe_run.mjs";

const ENGINE = process.env.ENGINE || "chromium";
const BASELINE = process.env.BASELINE_URL || "https://edge:8443/";
const TARGET = process.env.TARGET_URL;
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
  await page.waitForTimeout(4500);
  await maybeClick(page); // CLICK_SELECTOR triggers interaction-gated widgets before we read
  const rep = await collectAllFrames(page); // merged across all frames
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

// host-page framework + analytics + Playwright's own instrumentation is noise on a real site, not the widget
const NOISE = /(doubleclick|googletagmanager|google-analytics|google\.[a-z.]+\/(ccm|pagead|ads)|gstatic|googleadservices|\/cdn-cgi\/(rum|trace)|respond\.io|chatapi|facebook\.|hotjar|segment\.|sentry|clarity\.ms|__playwright)/i;
const targetHost = (() => {
  try {
    return new URL(TARGET).host;
  } catch (_) {
    return "";
  }
})();
// a challenge frame is a third-party frame (the widget's iframe), not the host page and not analytics
const isChallengeFrame = (h) => !!h && h !== targetHost && !/^about/.test(h) && !NOISE.test(h);
const inChallenge = (frames) => (frames || []).some(isChallengeFrame);

const sigDelta = tgt.signals.filter((s) => !baseSig.has(s.cat + ":" + s.name));
const lisDelta = tgt.behavioral.filter((b) => !baseLis.has(b.event) && !NOISE.test(b.event));
const epDelta = tgt.network.filter((n) => !basePath.has(pathOf(n.url)));

const gap = {
  baseline: BASELINE,
  target: TARGET,
  target_frames: [...new Set(tgt.frames)],
  challenge_frames: [...new Set(tgt.frames)].filter(isChallengeFrame),
  // full delta (raw)
  signals_target_only: sigDelta.map((s) => ({ cat: s.cat, name: s.name, samples: s.samples, frames: s.frames })),
  listeners_target_only: lisDelta.map((b) => b.event),
  endpoints_target_only: epDelta.map((n) => ({ method: n.method, url: n.url, body: n.body, frame: n.frame })),
  // noise-filtered + scoped to the challenge frame(s) — the clean VENDOR delta on a real production page
  challenge: {
    signals: sigDelta.filter((s) => inChallenge(s.frames)).map((s) => ({ cat: s.cat, name: s.name, samples: s.samples })),
    listeners: lisDelta.filter((b) => inChallenge(b.frames)).map((b) => b.event),
    endpoints: epDelta.filter((n) => isChallengeFrame(n.frame) && !NOISE.test(n.url)).map((n) => ({ method: n.method, url: n.url, body: n.body, frame: n.frame })),
  },
  covered: { signals: [...baseSig].length, listeners: [...baseLis].length },
};
console.log("__DIFF__" + JSON.stringify(gap));
