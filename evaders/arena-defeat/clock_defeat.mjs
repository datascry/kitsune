// evaders/arena-defeat/clock_defeat — drive a real browser to defeat the arena clock gate (pace + coherence probe).
// Loads the collector (clears net.no_js_execution), solves the clock in-page paced past the floor, reads the verdict.

// ETHICS: allow-list-scoped — targets ONLY Kitsune's own edge/arena (KITSUNE_EDGE/KITSUNE_DETECTOR). NEVER a
// third-party challenge. It grounds the arena-gate-DEFEAT thesis: a real browser trivially clears
// net.no_js_execution and (paced past the human floor) passes the gate with no speed anomaly — but a PLAIN
// browser then lights up the full per-session coherence surface (automation/webdriver/cdp/headless/behaviour/TLS),
// so DEFEAT (escaping conviction) requires the coherent+provisioned morph stack, not just running a browser.

import playwright from "playwright";

const ENGINE = process.env.ENGINE || "chromium";
const EDGE = process.env.KITSUNE_EDGE || "https://edge:8443";
const DETECTOR = process.env.KITSUNE_DETECTOR || "http://detector:8080";

const browser = await playwright[ENGINE].launch({
  headless: false,
  args: ENGINE === "chromium" ? ["--ignore-certificate-errors"] : [],
});
const context = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await context.newPage();

// 1) load the real collector page → JS executes → net.no_js_execution clears
await page.goto(EDGE + "/", { waitUntil: "domcontentloaded", timeout: 30000 });
for (let i = 0; i < 8; i++) await page.mouse.move(100 + i * 30, 120 + i * 17, { steps: 4 });
await page.waitForTimeout(2500); // let the collector POST its signals to /ingest

// 2) mint + solve the clock in-page (same origin/session), PACED past the 800ms floor, then verify.
//    createImageBitmap (not <img>) decodes the data URI — the collector page's CSP forbids data: images.
const solve = await page.evaluate(async () => {
  const c = await (await fetch("/arena/captcha?kind=clock&level=easy")).json();
  const bytes = Uint8Array.from(atob(c.image.split(",")[1]), (ch) => ch.charCodeAt(0));
  const bmp = await createImageBitmap(new Blob([bytes], { type: "image/png" }));
  const cv = document.createElement("canvas");
  cv.width = 100;
  cv.height = 100;
  const ctx = cv.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(bmp, 0, 0);
  const px = ctx.getImageData(0, 0, 100, 100).data;
  const dark = (x, y) => {
    const i = (y * 100 + x) * 4;
    return px[i] < 110 && px[i + 1] < 110 && px[i + 2] < 110;
  };
  const reach = [];
  for (let a = 0; a < 360; a++) {
    const rad = (a * Math.PI) / 180;
    const dx = Math.sin(rad);
    const dy = -Math.cos(rad);
    let run = 0;
    let miss = 0;
    for (let d = 3; d < 40; d++) {
      const x = Math.round(50 + d * dx);
      const y = Math.round(50 + d * dy);
      if (x >= 0 && x < 100 && y >= 0 && y < 100 && dark(x, y)) {
        run = d;
        miss = 0;
      } else {
        miss++;
        if (miss > 2) break;
      }
    }
    reach[a] = run;
  }
  let ma = 0;
  for (let a = 0; a < 360; a++) if (reach[a] > reach[ma]) ma = a;
  let ha = 0;
  for (let a = 0; a < 360; a++) {
    const dd = Math.min(Math.abs(a - ma), 360 - Math.abs(a - ma));
    if (dd > 18 && reach[a] > reach[ha]) ha = a;
  }
  const minute = Math.round(ma / 6) % 60;
  let hour = Math.round(ha / 30 - minute / 60) % 12;
  if (hour === 0) hour = 12;
  const answer = hour + ":" + String(minute).padStart(2, "0");
  await new Promise((r) => setTimeout(r, 2600)); // PACE past the 800ms human floor
  const v = await (
    await fetch("/arena/captcha/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ kind: "clock", id: c.id, answer }),
    })
  ).json();
  return { answer, ok: v.ok, anomaly: v.anomaly ?? null, token: !!v.token };
});

await page.waitForTimeout(1500);
const sid = (await context.cookies()).find((c) => c.name === "ks_sid")?.value;
const verdict = await (await fetch(`${DETECTOR}/verdict/${sid}`)).json();
const tells = (verdict.contradictions || []).map((c) => c.rule_id).sort();
console.log("__DEFEAT__" + JSON.stringify({ engine: ENGINE, sid, solve, label: verdict.label, tells }));

await browser.close();
