// harness/tools/chrome_quic_capture — capture a REAL Chrome QUIC ClientHello through the live edge.
// Drives stock headful Chromium with QUIC enabled, navigates twice so Chrome attempts h3 after Alt-Svc.

import playwright from "playwright";

const EDGE = process.env.KITSUNE_EDGE || "https://edge:8443/";
const DETECTOR = process.env.KITSUNE_DETECTOR || "http://detector:8080";

// Stock Chromium, QUIC enabled, cert-ignore for the edge's self-signed TLS. NO stealth/spoof args — this is
// a genuine Chrome whose QUIC ClientHello is real BoringSSL ground truth for the quic_no_grease question.
const browser = await playwright.chromium.launch({
  headless: false,
  args: ["--ignore-certificate-errors", "--enable-quic"],
});
const context = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await context.newPage();

// Nav 1 over h2/TCP: receives the edge's `Alt-Svc: h3` advert and caches it.
await page.goto(EDGE, { waitUntil: "domcontentloaded", timeout: 30000 });
await page.waitForTimeout(2000);
// Nav 2+: Chrome now races h3 (QUIC) against h2 for the cached Alt-Svc origin → emits a QUIC Initial the
// edge captures (the h3 attempt itself fails as the capturer closes, so the page still loads over h2).
for (let i = 0; i < 12; i++) {
  await page.goto(EDGE + "?n=" + i, { waitUntil: "domcontentloaded", timeout: 30000 }).catch(() => {});
  await page.waitForTimeout(1200);
}
await page.waitForTimeout(2000);

const cookies = await context.cookies();
const sid = cookies.find((c) => c.name === "ks_sid")?.value;
if (!sid) throw new Error("no ks_sid cookie — edge did not mint a session");

const session = await (await fetch(`${DETECTOR}/session/${sid}`)).json();
const net = Object.fromEntries(session.signals.network.map((s) => [s.kind, s.value]));
console.log(
  "__QUIC__" +
    JSON.stringify({
      sid,
      quic_observed: net.quic_observed ?? null,
      quic_no_grease: net.quic_no_grease ?? null,
      quic_no_pq_keyshare: net.quic_no_pq_keyshare ?? null,
    }),
);

await browser.close();
