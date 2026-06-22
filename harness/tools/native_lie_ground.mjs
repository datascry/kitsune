// harness/tools/native_lie_ground — ground the S4 native-lie battery (exact own-keys + proxy-over-native).
// Across real Chromium/Firefox/WebKit: FP baseline (real native methods' own-keys) + EVADES/CONVICTS of a wrapper.

// S4 (docs/detection-landscape.md): the current native_invariant check (toString native? own prototype?
// constructible?) is defeated by a Proxy-over-native method (reflects "[native code]", no own prototype,
// non-constructible). CreepJS's distinguishing test is the EXACT own-key set: a real native function's
// Reflect.ownKeys is exactly [length,name]. This probe (1) records that set for real native methods across
// three engines — the FP baseline that must be exactly [length,name] for the rule to be FP-safe — and
// (2) confirms a Proxy/sloppy wrapper EVADES the current checks while exact-own-keys / a proxy-trap catches it.

import playwright from "playwright";

const METHODS = [
  "navigator.permissions.query",
  "HTMLCanvasElement.prototype.toDataURL",
  "navigator.mediaDevices.enumerateDevices",
  "WebGLRenderingContext.prototype.getParameter",
  "Function.prototype.bind",
  "navigator.userAgentData && navigator.userAgentData.getHighEntropyValues",
];

const PROBE = `(() => {
  const out = { baseline: [], evader: null };
  const get = (path) => { try { return eval(path); } catch (e) { return undefined; } };
  for (const path of ${JSON.stringify(METHODS)}) {
    const fn = get(path);
    if (typeof fn !== "function") { out.baseline.push({ path, present: false }); continue; }
    const keys = Reflect.ownKeys(fn).map(String).sort();
    out.baseline.push({ path, present: true, ownKeys: keys, native: fn.toString().includes("[native code]") });
  }
  // EVADER: Proxy-over-native + sloppy wrapper around navigator.permissions.query.
  try {
    const real = navigator.permissions.query.bind(navigator.permissions);
    const realNative = navigator.permissions.query;
    const proxied = new Proxy(realNative, { apply: (t, th, a) => Reflect.apply(t, th, a) });
    const sloppy = function query() { return real.apply(null, arguments); };
    sloppy.__orig = realNative; // a marker an exact-own-keys check would catch
    const checks = (fn) => ({
      claimsNative: typeof fn === "function" && fn.toString().includes("[native code]"),
      ownProto: Object.prototype.hasOwnProperty.call(fn, "prototype"),
      constructible: (() => { try { new fn(); return true; } catch (e) { return false; } })(),
      ownKeys: Reflect.ownKeys(fn).map(String).sort(),
    });
    out.evader = { proxied: checks(proxied), sloppy: checks(sloppy) };
  } catch (e) { out.evader = { error: String(e) }; }
  return out;
})()`;

for (const engine of ["chromium", "firefox", "webkit"]) {
  const launcher = playwright[engine];
  let browser;
  try {
    browser = await launcher.launch({ headless: false });
  } catch (e) {
    console.log(`__SKIP__ ${engine}: ${e.message.split("\\n")[0]}`);
    continue;
  }
  const page = await (await browser.newContext({ ignoreHTTPSErrors: true })).newPage();
  await page.goto("about:blank");
  const res = await page.evaluate(PROBE);
  console.log(`__ENGINE__ ${engine}`);
  for (const b of res.baseline) console.log("  base " + JSON.stringify(b));
  console.log("  evader " + JSON.stringify(res.evader));
  await browser.close();
}
