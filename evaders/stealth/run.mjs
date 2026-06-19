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
// HEADFUL=1: launch headless:false (run via xvfb-run). A headful Chromium's UA + Sec-CH-UA carry no
// HeadlessChrome token, so headless-reveal tells (ch_he_headless/headless_ua) do not auto-fire — this is
// how we test browser-layer evasion under patchright with a NATURAL coherent UA (no override that, under
// patchright, breaks the page collector — see docs/evasion-catalog.md). Pair with PATCHRIGHT=1.
const HEADFUL = process.env.HEADFUL === "1";
// KS_PROXY=<url>: route this context's traffic through a proxy (http(s)://, socks5://) so the edge observes
// a REAL egress IP instead of the private container IP. The turnkey hook for the live proxy/coordination
// harness: point a fleet at residential/datacenter proxies and rep.datacenter_asn / rep.known_proxy_exit /
// net.webrtc_ip_vs_observed + the proxy-topology coordination signals fire on real IPs. Target stays the
// allow-listed edge; the proxy is only the egress path (ethics: TARGET unchanged). See docs/coordination-proxy.md.
const KS_PROXY = process.env.KS_PROXY;
// MAX_STEALTH: the kitchen sink — patchright (best CDP stealth) + a coherent Linux-Chrome UA (no headless
// token) + human-like motion. The chromium analog of hardened-Camoufox: what survives maximal stealth.
const MAX_STEALTH = process.env.MAX_STEALTH === "1";
// FLOOR_SPOOF: the red-team frontier — attack the *environment floor* every tool hits. Patchright (clean
// CDP stealth) + a coherent Linux-Chrome UA, then fake the two tells nothing else spoofs: speechSynthesis
// voices and enumerateDevices. Tests whether voices_empty/media_devices_empty are a real wall or just
// catch the lazy (absent) case — and whether the detector catches the *spoof* via coherence instead.
const FLOOR_SPOOF = process.env.FLOOR_SPOOF === "1";
// WORKER_SPOOF: the context-isolation gap. A JS-injection spoof (addInitScript / Object.defineProperty)
// patches navigator in the main realm and its iframes, but NOT Web Worker global scope — a Worker reads
// the real hardwareConcurrency/userAgent. Spoof only the main thread (the lazy way most UA/hardware
// spoofers do) and the detector's worker_divergence probe catches the realm the patch never reached.
const WORKER_SPOOF = process.env.WORKER_SPOOF === "1";
// IFRAME_SPOOF: the sibling context-isolation gap. The spoof guards on window.top===window, so it only
// rewrites the top frame's navigator (the lazy pattern). A dynamically-created same-origin iframe gets
// its own, un-patched navigator → the detector's iframe_divergence probe catches the realm the patch
// skipped. Distinct from WORKER_SPOOF (a prototype patch reaches iframes but never Worker scope).
const IFRAME_SPOOF = process.env.IFRAME_SPOOF === "1";
// NATIVE_SPOOF: the prototype-invariant gap. A naive GPU spoof replaces WebGLRenderingContext.getParameter
// with a plain function and fakes its toString to "[native code]" to beat tostring_tampered — but a plain
// function has an own `prototype` and is constructable, which a real built-in never is. The detector's
// native-invariant suite checks exactly that, so the deeper structural lie is caught where toString isn't.
const NATIVE_SPOOF = process.env.NATIVE_SPOOF === "1";
// LINEAR_BOT: the behavioral floor. Drag the cursor in a single straight line at constant velocity —
// straightness → 1.0 (> bh.path_too_straight 0.97) and velocity CV → 0 (< bh.uniform_velocity 0.08).
// The fleet's human-mouse mode (bezier curves, eased velocity) is the negative control that must NOT trip
// these, so this pair demonstrates the biomech rules discriminate scripted motion from human motion.
const LINEAR_BOT = process.env.LINEAR_BOT === "1";
// CANVAS_SPOOF: the canvas realm-isolation gap. A JS canvas-noise spoof perturbs the main realm's 2D
// getImageData (and iframes) but never reaches Worker scope, so a Worker OffscreenCanvas renders clean →
// canvas_worker_vs_main catches the realm the farble skipped. The canvas analog of WORKER_SPOOF.
const CANVAS_SPOOF = process.env.CANVAS_SPOOF === "1";
// TZ_SPOOF: the geo-spoof realm gap. A residential-proxy bot patches Intl/Date on the main thread to
// match the proxy's country, but a JS patch never reaches Worker scope, so a Worker reports the real host
// timezone → timezone_worker_vs_main. The geo analog of WORKER_SPOOF.
const TZ_SPOOF = process.env.TZ_SPOOF === "1";
// LANG_SPOOF: the language half of the geo-spoof realm pair. Patch navigator.languages in the main realm
// to match the proxy's country; the patch never reaches Worker scope → languages_worker_vs_main.
const LANG_SPOOF = process.env.LANG_SPOOF === "1";
// WORKER_WRAP: the realm-coherence escalation. Wrap window.Worker so worker code is prefixed with the
// same navigator spoof (via importScripts of the original blob) — the worker now AGREES with the main
// thread, defeating worker_divergence. But the wrapped Worker constructor is no longer native, so
// br.worker_constructor_tampered catches the realm the spoof had to compromise to hide.
const WORKER_WRAP = process.env.WORKER_WRAP === "1";
// NAIVE_TZ_SPOOF: the one-field geo-spoof. Patch ONLY Intl.resolvedOptions().timeZone (claim a proxy-
// matching zone) and forget Date.getTimezoneOffset — the offset then contradicts the claimed zone →
// br.timezone_offset_vs_intl. The canonical incomplete timezone spoof.
const NAIVE_TZ_SPOOF = process.env.NAIVE_TZ_SPOOF === "1";
// AUDIO_READBACK_SPOOF: the audio analog of CANVAS_SPOOF. A naive audio-farble patches the
// fingerprint-readable AudioBuffer.getChannelData path to perturb the samples, but forgets copyFromChannel
// (which reads the SAME buffer). On a real engine the two paths are bit-identical; the inconsistent shim
// makes them diverge → br.readback_noise. Exercises the experimental readback_noise rule (previously
// unexercised by the fleet — no other evader perturbs the audio readback inconsistently).
const AUDIO_READBACK_SPOOF = process.env.AUDIO_READBACK_SPOOF === "1";
// LANG_LIST_SPOOF: the one-field locale spoof. Patch navigator.language (claim a proxy-matching language)
// but leave navigator.languages real — the HTML spec makes them identical, so they now disagree →
// br.language_vs_languages. The language analog of NAIVE_TZ_SPOOF.
const LANG_LIST_SPOOF = process.env.LANG_LIST_SPOOF === "1";
// CANVAS_GEOMETRY_SPOOF: the JShelter canvas-geometry farble. Wrap isPointInPath to flip its boolean ~5% of
// the time to poison fingerprinting — but the hit-test is exact in a real engine, so a point deep inside a
// filled path must always read in-path → br.canvas_geometry_noise.
const CANVAS_GEOMETRY_SPOOF = process.env.CANVAS_GEOMETRY_SPOOF === "1";
// BRAVE_FAKE: inject a fake navigator.brave to claim Brave (and try to get the privacy-browser farbling
// N/A) — but a real Brave's navigator.brave.isBrave is NATIVE; the injected one is a plain function →
// br.brave_spoofed (and the genuineness guard withholds the N/A).
const BRAVE_FAKE = process.env.BRAVE_FAKE === "1";
// RENDERER_SPOOF: a naive GPU-masking spoof — patch WebGL getParameter so the UNMASKED_RENDERER reports a
// generic placeholder ("Generic Renderer") to hide the real/SwiftShader GPU. Under a Chromium UA (which
// never generalises its renderer the way Firefox does) the placeholder string trips br.webgl_renderer_artifact.
// Gives that rule a live Blink positive after v0.74.10 scoped it off the (legitimately-generalising) Gecko engine.
const RENDERER_SPOOF = process.env.RENDERER_SPOOF === "1";
// HONEYPOT: the naive "interact with everything" scraper/form-spammer — enumerate the DOM and click every
// link + fill every text input. It blindly trips the collector's off-screen aria-hidden honeypot bait (a
// link/input a human cannot reach) → br.honeypot_interaction. A real browser navigated by a human never does.
const HONEYPOT = process.env.HONEYPOT === "1";
// ACCEPT_LANG_SPOOF: the cross-layer locale gap. A geo-spoof patches navigator.language/languages in JS to
// the proxy's country (fr) but the browser still sends its real HTTP Accept-Language header (en) — the bot
// forgot the network layer. The HTTP header and the JS locale now disagree → net.accept_lang_vs_navigator.
// (context locale=en-US makes the real Accept-Language deterministic so the mismatch is clean.)
const ACCEPT_LANG_SPOOF = process.env.ACCEPT_LANG_SPOOF === "1";
// ELECTRON_LEAK: an Electron/automation runtime whose renderer exposes a Node `process` (nodeIntegration on).
// Inject process.versions.electron + process.type="renderer" — the markers a real Electron renderer leaks and
// a real web browser never has → br.electron_process (an active automation rule with no prior live positive).
const ELECTRON_LEAK = process.env.ELECTRON_LEAK === "1";

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
const evading =
  STEALTH ||
  FULL ||
  MAX_STEALTH ||
  FLOOR_SPOOF ||
  WORKER_SPOOF ||
  IFRAME_SPOOF ||
  NATIVE_SPOOF ||
  CANVAS_SPOOF ||
  TZ_SPOOF ||
  LANG_SPOOF ||
  WORKER_WRAP ||
  NAIVE_TZ_SPOOF ||
  AUDIO_READBACK_SPOOF ||
  LANG_LIST_SPOOF ||
  CANVAS_GEOMETRY_SPOOF ||
  BRAVE_FAKE ||
  ELECTRON_LEAK ||
  Boolean(SPOOF_UA);
const mode = ELECTRON_LEAK
  ? "electron-leak"
  : ACCEPT_LANG_SPOOF
  ? "accept-lang-spoof"
  : HONEYPOT
  ? "honeypot"
  : RENDERER_SPOOF
  ? "renderer-spoof"
  : BRAVE_FAKE
  ? "brave-fake"
  : CANVAS_GEOMETRY_SPOOF
    ? "canvas-geometry-spoof"
    : LANG_LIST_SPOOF
      ? "lang-list-spoof"
      : AUDIO_READBACK_SPOOF
        ? "audio-readback-spoof"
        : NAIVE_TZ_SPOOF
    ? "naive-tz-spoof"
    : WORKER_WRAP
  ? "worker-wrap"
  : LANG_SPOOF
  ? "lang-spoof"
  : TZ_SPOOF
  ? "tz-spoof"
  : CANVAS_SPOOF
  ? "canvas-spoof"
  : LINEAR_BOT
  ? "linear-bot"
  : NATIVE_SPOOF
  ? "native-spoof"
  : IFRAME_SPOOF
  ? "iframe-spoof"
  : WORKER_SPOOF
  ? "worker-spoof"
  : FLOOR_SPOOF
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
const browser = await chromium.launch({ headless: !HEADFUL, args: ["--no-sandbox", "--ignore-certificate-errors"] });
const context = await browser.newContext({
  ignoreHTTPSErrors: true,
  ...(userAgent ? { userAgent } : {}),
  // Pin the HTTP Accept-Language so ACCEPT_LANG_SPOOF's JS-vs-header locale mismatch is deterministic.
  ...(ACCEPT_LANG_SPOOF ? { locale: "en-US" } : {}),
  // Route through a real proxy so the edge sees a real egress IP (turnkey live-proxy harness hook).
  ...(KS_PROXY ? { proxy: { server: KS_PROXY } } : {}),
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
    // Fake the PDF floor: pdfViewerEnabled true and a non-empty mimeTypes, the naive way (define on the
    // navigator instance). A real browser carries these as prototype-inherited accessors, so an own
    // property is itself the tell — the same lie detection plugins_spoofed already uses.
    Object.defineProperty(navigator, "pdfViewerEnabled", { get: () => true, configurable: true });
    Object.defineProperty(navigator, "mimeTypes", {
      get: () => [{ type: "application/pdf", suffixes: "pdf", description: "Portable Document Format" }],
      configurable: true,
    });
    // Fake the notification floor: headless Chrome defaults Notification.permission to "denied"; claim
    // "default" instead to beat br.notification_denied. The catch is that the Permissions API still
    // reports the real state, so permission and query must stay coherent — see the bidirectional permAnomaly.
    try {
      Object.defineProperty(Notification, "permission", { get: () => "default", configurable: true });
    } catch (e) {}
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
} else if (WORKER_SPOOF) {
  // Spoof navigator in the MAIN realm only — the lazy hardware/UA spoof. hardwareConcurrency is dropped
  // to 2 and the UA is rewritten in-page; both patches live on the main thread and its iframes but never
  // reach Worker global scope, so the collector's Blob worker reports the real values → worker_divergence.
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    Object.defineProperty(Navigator.prototype, "hardwareConcurrency", { get: () => 2, configurable: true });
  });
} else if (IFRAME_SPOOF) {
  // Spoof navigator.userAgent in the TOP frame only (guarded on window.top===window). A same-origin
  // iframe the collector creates later is not the top frame, so it keeps the real UA → iframe_divergence.
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    if (window.top === window.self) {
      Object.defineProperty(Navigator.prototype, "userAgent", {
        get: () => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        configurable: true,
      });
    }
  });
} else if (NATIVE_SPOOF) {
  // Replace getParameter with a plain function and fake its toString to "[native code]" — beating
  // tostring_tampered, but the plain function carries an own `prototype` and is constructable, which a
  // real built-in never is → native_invariant_violated catches the structural lie toString cannot.
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    const gp = WebGLRenderingContext.prototype.getParameter;
    const fake = function getParameter(p) {
      if (p === 37446) return "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)";
      return gp.call(this, p);
    };
    fake.toString = () => "function getParameter() { [native code] }";
    WebGLRenderingContext.prototype.getParameter = fake;
  });
} else if (CANVAS_SPOOF) {
  // Main-realm-only canvas farble: perturb getImageData output on the 2D prototype (reaches the page and
  // iframes) but never Worker scope, so a Worker OffscreenCanvas hashes clean → canvas_worker_vs_main.
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    const gid = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function (...a) {
      const r = gid.apply(this, a);
      for (let i = 0; i < r.data.length; i += 499) r.data[i] = r.data[i] ^ 1; // 1-bit per-session farble
      return r;
    };
  });
} else if (AUDIO_READBACK_SPOOF) {
  // Inconsistent audio farble: perturb ONE of the two AudioBuffer readback paths. The detector writes the
  // buffer via getChannelData then reads it back via copyFromChannel and diffs them — on a real engine they
  // are bit-identical, so perturbing the copyFromChannel readback alone makes them diverge → readback_noise.
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    const cfc = AudioBuffer.prototype.copyFromChannel;
    AudioBuffer.prototype.copyFromChannel = function (dest, ...rest) {
      cfc.call(this, dest, ...rest);
      for (let i = 0; i < dest.length; i += 100) dest[i] += 1e-7; // perturb the readback copy only
    };
  });
} else if (LANG_LIST_SPOOF) {
  // One-field locale spoof: claim navigator.language = pt-BR but leave navigator.languages real. The HTML
  // spec defines language as languages[0], so they now disagree → br.language_vs_languages.
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    Object.defineProperty(Navigator.prototype, "language", { get: () => "pt-BR", configurable: true });
  });
} else if (CANVAS_GEOMETRY_SPOOF) {
  // JShelter-style canvas-geometry farble: wrap isPointInPath to flip its boolean ~5% of the time. The
  // hit-test is exact in a real engine, so a point deep inside a filled path is ALWAYS in-path → over many
  // trials the flip betrays itself → br.canvas_geometry_noise.
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    const ipp = CanvasRenderingContext2D.prototype.isPointInPath;
    CanvasRenderingContext2D.prototype.isPointInPath = function (...a) {
      const r = ipp.apply(this, a);
      return Math.random() < 0.05 ? !r : r;
    };
  });
} else if (BRAVE_FAKE) {
  // Fake the Brave identity: inject navigator.brave to claim Brave (and try to earn the privacy-browser
  // farbling N/A). But a real Brave's navigator.brave.isBrave is NATIVE; this plain function is not →
  // br.brave_spoofed, and the genuineness guard refuses the N/A.
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    Object.defineProperty(navigator, "brave", {
      value: { isBrave: () => Promise.resolve(true) },
      configurable: true,
    });
  });
} else if (RENDERER_SPOOF) {
  // Naive GPU-masking: patch WebGL getParameter so the UNMASKED_RENDERER (0x9246) reports a generic
  // placeholder, hiding the real/SwiftShader GPU. Under a Chromium UA the placeholder trips
  // br.webgl_renderer_artifact (Chromium never generalises its renderer like Firefox's "…, or similar").
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    const UNMASKED_RENDERER = 0x9246;
    for (const proto of [window.WebGLRenderingContext, window.WebGL2RenderingContext]) {
      if (!proto) continue;
      const gp = proto.prototype.getParameter;
      proto.prototype.getParameter = function (p) {
        return p === UNMASKED_RENDERER ? "Generic Renderer" : gp.call(this, p);
      };
    }
  });
} else if (ACCEPT_LANG_SPOOF) {
  // Patch the JS locale to fr (a proxy-country geo-spoof) while the context's HTTP Accept-Language stays
  // en-US — the bot spoofed navigator but forgot the network layer. nav_language_primary=fr vs
  // accept_language_primary=en → net.accept_lang_vs_navigator. Both navigator.language AND languages are
  // patched coherently (fr) so the JS layer is internally consistent and ONLY the HTTP header disagrees.
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    Object.defineProperty(navigator, "language", { get: () => "fr-FR", configurable: true });
    Object.defineProperty(navigator, "languages", { get: () => ["fr-FR", "fr"], configurable: true });
  });
} else if (TZ_SPOOF) {
  // Main-realm-only geo-spoof: claim America/New_York via Intl + Date on the main thread. The patch never
  // reaches Worker scope, so a Worker reports the real host timezone → timezone_worker_vs_main.
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    const RTO = Intl.DateTimeFormat.prototype.resolvedOptions;
    Intl.DateTimeFormat.prototype.resolvedOptions = function () {
      const o = RTO.call(this);
      o.timeZone = "America/New_York";
      return o;
    };
    Date.prototype.getTimezoneOffset = function () {
      return 300;
    };
  });
} else if (LANG_SPOOF) {
  // Main-realm-only geo-spoof: claim French via navigator.languages on the main thread. The patch never
  // reaches Worker scope, so a Worker reports the real host languages → languages_worker_vs_main.
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    Object.defineProperty(Navigator.prototype, "languages", { get: () => ["fr-FR", "fr"], configurable: true });
  });
} else if (WORKER_WRAP) {
  // Escalation: spoof hardwareConcurrency on main AND wrap window.Worker so each worker imports the
  // original script behind the same spoof — defeating worker_divergence. The wrap makes window.Worker a
  // non-native plain function → br.worker_constructor_tampered.
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    Object.defineProperty(Navigator.prototype, "hardwareConcurrency", { get: () => 2, configurable: true });
    const RealWorker = window.Worker;
    const SPOOF = "Object.defineProperty(self.navigator,'hardwareConcurrency',{get:function(){return 2}});";
    window.Worker = function (url, opts) {
      const wrapped = SPOOF + "importScripts('" + url + "');";
      return new RealWorker(URL.createObjectURL(new Blob([wrapped], { type: "application/javascript" })), opts);
    };
    window.Worker.prototype = RealWorker.prototype;
  });
} else if (NAIVE_TZ_SPOOF) {
  // One-field geo-spoof: patch only Intl.resolvedOptions().timeZone, leave Date.getTimezoneOffset real, so
  // the offset contradicts the claimed zone → br.timezone_offset_vs_intl.
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    const RTO = Intl.DateTimeFormat.prototype.resolvedOptions;
    Intl.DateTimeFormat.prototype.resolvedOptions = function () {
      const o = RTO.call(this);
      o.timeZone = "America/New_York";
      return o;
    };
  });
} else if (ELECTRON_LEAK) {
  // Leak a Node `process` into the renderer the way an Electron app with nodeIntegration on (or a naive
  // automation runtime) does — process.versions.electron + process.type="renderer". A real web browser has
  // no Node process at all, so the collector's Electron-marker check trips → br.electron_process. (Gated to
  // the Electron-specific markers, so this is NOT a generic process.env/webpack shim — it is the real tell.)
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
    Object.defineProperty(window, "process", {
      value: { type: "renderer", versions: { electron: "31.3.0", node: "20.15.0", chrome: "126.0.0.0" } },
      configurable: true,
    });
  });
} else if (evading) {
  await context.addInitScript(() => {
    Object.defineProperty(navigator, "webdriver", { get: () => false });
  });
}

const page = await context.newPage();
await page.goto(EDGE, { waitUntil: "load" });
const human = HUMAN_MOUSE || MAX_STEALTH;
if (HONEYPOT) {
  // Naive form-spammer: enumerate the DOM and fill every text input + dispatch a click on every link. A
  // human reaches only the visible page; this blindly trips the off-screen aria-hidden honeypot bait (input
  // email_confirm / link #ks-hp) → br.honeypot_interaction. dispatchEvent (not .click()) and value-set never
  // navigate the document, so the collector survives to report. Bait was appended at DOMContentLoaded.
  await page.evaluate(() => {
    try {
      document.querySelectorAll('input[type="text"]').forEach((i) => {
        i.value = "bot@example.com";
      });
      document.querySelectorAll("a").forEach((a) => {
        a.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      });
    } catch (e) {}
  });
  // The interaction is instant (unlike the typing/mouse paths), so keep the page alive long enough for the
  // collector's send (1200ms timer + edge round-trip ≈ 2.5s) to fire — the shared 2s wait below alone is short.
  await page.waitForTimeout(2500);
} else if (LINEAR_BOT) {
  // Scripted motion: a single straight-line drag at constant velocity (fixed pixel step + fixed delay).
  // straightness → 1.0 and velocity CV → 0, tripping bh.path_too_straight and bh.uniform_velocity.
  const from = { x: 100, y: 120 };
  const to = { x: 760, y: 520 };
  const steps = 24;
  for (let i = 1; i <= steps; i++) {
    await page.mouse.move(from.x + ((to.x - from.x) * i) / steps, from.y + ((to.y - from.y) * i) / steps);
    // A longer fixed interval keeps dispatch jitter a small fraction of dt, so velocity CV stays under the
    // uniform_velocity floor (0.08) — at 20ms the ~few-ms jitter alone pushed CV to ~0.19.
    await page.waitForTimeout(75);
  }
} else if (human) {
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
