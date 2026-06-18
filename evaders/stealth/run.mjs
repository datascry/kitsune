// evaders/stealth/run — drive a real Chromium through the edge and read the detector's verdict.
// Modes: naive (automation tells) · STEALTH=1 (patched) · SPOOF_UA=<ua> (Chrome TLS, lying UA).

const EDGE = process.env.KITSUNE_EDGE || "https://edge:8443/";
const DETECTOR = process.env.KITSUNE_DETECTOR || "http://detector:8080";
const STEALTH = process.env.STEALTH === "1";
const FULL = process.env.FULL === "1"; // contest the whole v0.4.0 browser battery
const SPOOF_UA = process.env.SPOOF_UA; // e.g. a Firefox UA, while the real TLS stays Chrome
const PATCHRIGHT = process.env.PATCHRIGHT === "1"; // CDP-patched anti-detect drop-in for Playwright
const REBROWSER = process.env.REBROWSER === "1"; // rebrowser-patches: another Runtime.enable-leak fix
const HUMAN_MOUSE = process.env.HUMAN_MOUSE === "1"; // synthesize human-like motion vs the naive path
// MAX_STEALTH: the kitchen sink — patchright (best CDP stealth) + a coherent Linux-Chrome UA (no headless
// token) + human-like motion. The chromium analog of hardened-Camoufox: what survives maximal stealth.
const MAX_STEALTH = process.env.MAX_STEALTH === "1";
// FLOOR_SPOOF: the red-team frontier — attack the *environment floor* every tool hits. Patchright (clean
// CDP stealth) + a coherent Linux-Chrome UA, then fake the two tells nothing else spoofs: speechSynthesis
// voices and enumerateDevices. Tests whether voices_empty/media_devices_empty are a real wall or just
// catch the lazy (absent) case — and whether the detector catches the *spoof* via coherence instead.
const FLOOR_SPOOF = process.env.FLOOR_SPOOF === "1";

// A cubic Bézier point — humans move in curves, not straight lines or perfect sines.
function bezier(p0, p1, p2, p3, t) {
  const u = 1 - t;
  return {
    x: u * u * u * p0.x + 3 * u * u * t * p1.x + 3 * u * t * t * p2.x + t * t * t * p3.x,
    y: u * u * u * p0.y + 3 * u * u * t * p1.y + 3 * u * t * t * p2.y + t * t * t * p3.y,
  };
}

// Move along a curved path with ease-in-out velocity (slow-fast-slow), micro-jitter (tremor), and
// variable inter-event timing — the three traits the behavioral rules look for the *absence* of.
async function humanMove(page, from, to) {
  const c1 = { x: from.x + (Math.random() - 0.5) * 250, y: from.y + (Math.random() - 0.5) * 250 };
  const c2 = { x: to.x + (Math.random() - 0.5) * 250, y: to.y + (Math.random() - 0.5) * 250 };
  const steps = 25 + Math.floor(Math.random() * 20);
  for (let i = 1; i <= steps; i++) {
    const lin = i / steps;
    const t = lin < 0.5 ? 2 * lin * lin : 1 - Math.pow(-2 * lin + 2, 2) / 2; // ease-in-out
    const p = bezier(from, c1, c2, to, t);
    await page.mouse.move(p.x + (Math.random() - 0.5) * 2, p.y + (Math.random() - 0.5) * 2);
    await page.waitForTimeout(6 + Math.random() * 22);
  }
}

// patchright / rebrowser-playwright are API-compatible playwright drop-ins; swap the engine at runtime.
const engine =
  PATCHRIGHT || MAX_STEALTH || FLOOR_SPOOF ? "patchright" : REBROWSER ? "rebrowser-playwright" : "playwright";
const { chromium } = await import(engine);

const CHROME_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
// Coherent with the container's real Linux platform (no headless token, Linux Client-Hints).
const LINUX_CHROME_UA =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

const userAgent =
  SPOOF_UA || (MAX_STEALTH || FULL || FLOOR_SPOOF ? LINUX_CHROME_UA : STEALTH ? CHROME_UA : undefined);
const evading = STEALTH || FULL || MAX_STEALTH || FLOOR_SPOOF || Boolean(SPOOF_UA);
const mode = FLOOR_SPOOF
  ? "floor-spoof"
  : MAX_STEALTH
    ? "max-stealth"
    : HUMAN_MOUSE
      ? "human-mouse"
      : PATCHRIGHT
        ? "patchright"
        : REBROWSER
          ? "rebrowser"
          : FULL
            ? "full-stealth"
            : SPOOF_UA
              ? "spoof-ua"
              : STEALTH
                ? "stealth"
                : "naive";

// --ignore-certificate-errors: accept the edge's self-signed cert at the TLS layer (not just the
// navigation layer) so the fingerprinting handshake completes and network signals are captured.
const browser = await chromium.launch({ args: ["--no-sandbox", "--ignore-certificate-errors"] });
const context = await browser.newContext({
  ignoreHTTPSErrors: true,
  ...(userAgent ? { userAgent } : {}),
});
if (FLOOR_SPOOF) {
  // Attack the environment floor: fake the presence of the two tells nothing else spoofs. Voices are
  // given Linux-desktop (espeak-style) names so they are coherent with the Linux UA — no Microsoft/Apple
  // markers that would trip br.voice_os_vs_ua. Devices mimic a real pre-permission enumeration (present
  // kinds, empty labels). webdriver/chrome are patched too; WebGL is left real to avoid the tampering tell.
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    if (!window.chrome) Object.defineProperty(window, "chrome", { value: { runtime: {} } });
    const fakeVoices = [
      { name: "English (America)", lang: "en-US", default: true, localService: true, voiceURI: "english-us" },
      { name: "English (Great Britain)", lang: "en-GB", default: false, localService: true, voiceURI: "english-gb" },
      { name: "español", lang: "es-ES", default: false, localService: true, voiceURI: "spanish" },
    ];
    if (window.speechSynthesis) window.speechSynthesis.getVoices = () => fakeVoices;
    const fakeDevices = [
      { deviceId: "default", kind: "audioinput", label: "", groupId: "g1" },
      { deviceId: "default", kind: "audiooutput", label: "", groupId: "g1" },
      { deviceId: "cam0", kind: "videoinput", label: "", groupId: "g2" },
    ];
    if (navigator.mediaDevices) {
      navigator.mediaDevices.enumerateDevices = () =>
        Promise.resolve(fakeDevices.map((d) => ({ ...d, toJSON: () => d })));
    }
  });
} else if (FULL) {
  // The full battery: every patch a JS-injection anti-detect would apply. Note webdriver is patched
  // on Navigator.prototype (no own-property tell), and WebGL is given a real GPU string.
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    if (!window.chrome) Object.defineProperty(window, "chrome", { value: { runtime: {} } });
    Object.defineProperty(navigator, "plugins", {
      get: () => [{ name: "Chrome PDF Plugin" }, { name: "Chrome PDF Viewer" }, { name: "Native Client" }],
    });
    const gp = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function (p) {
      if (p === 37445) return "Google Inc. (NVIDIA)";
      if (p === 37446) return "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)";
      return gp.call(this, p);
    };
  });
} else if (evading) {
  await context.addInitScript(() => {
    Object.defineProperty(navigator, "webdriver", { get: () => false });
  });
}

const page = await context.newPage();
await page.goto(EDGE, { waitUntil: "load" });
const human = HUMAN_MOUSE || MAX_STEALTH;
if (human) {
  // Human-like curved moves between random targets — the behavioral evasion frontier (mouse only, to
  // keep this a clean behavioral-evasion demo within the collector's capture window).
  let pos = { x: 120, y: 140 };
  for (let i = 0; i < 4; i++) {
    const to = { x: 80 + Math.random() * 600, y: 80 + Math.random() * 400 };
    await humanMove(page, pos, to);
    pos = to;
    await page.waitForTimeout(120 + Math.random() * 280); // human dwell between gestures
  }
} else {
  // Naive bot: fixed-delay typing first (within the capture window) — the uniform inter-key interval
  // collapses keystroke entropy toward 0, tripping bh.keystroke_entropy_floor (humans vary digraph
  // latencies) — then a simple mouse path.
  for (const ch of "the quick brown fox") {
    await page.keyboard.type(ch);
    await page.waitForTimeout(95);
  }
  for (let i = 0; i < 24; i++) {
    await page.mouse.move(100 + i * 7, 120 + Math.sin(i / 2) * 50);
  }
}
await page.waitForTimeout(2000); // let the in-page collector post its signals

const ks = (await context.cookies()).find((c) => c.name === "ks_sid");
if (!ks) {
  console.error("no ks_sid cookie — pipeline not wired");
  process.exit(2);
}
const verdict = await (await fetch(`${DETECTOR}/verdict/${ks.value}`)).json();
// Sentinel-prefixed compact line so the orchestrator can extract it even if the engine (e.g.
// patchright) writes other noise to stdout.
console.log("__KS__" + JSON.stringify({ mode, ...verdict }));
await browser.close();
