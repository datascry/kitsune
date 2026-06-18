# detector/demo — the in-browser demo page served to real (or evader-driven) browsers.
# Inline collector mirroring the TS collector library; posts browser+behavioral signals to /ingest.

"""The demo page.

A real browser loads this (through the edge, which fingerprints the TLS handshake and sets ``ks_sid``).
The inline script reads ``ks_sid``, collects the same browser/behavioral tells the TypeScript
``collector`` library does, and POSTs them to ``/ingest`` (same origin → proxied to the detector),
joining the network signals into one session.
"""

from __future__ import annotations

DEMO_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Kitsune</title></head>
<body><h1>Kitsune lab</h1><p>collecting…</p>
<script>
(function () {
  function sid() { var m = document.cookie.match(/(?:^|; )ks_sid=([^;]+)/); return m ? decodeURIComponent(m[1]) : null; }
  var id = sid();
  if (!id) { return; }
  var pts = [];
  addEventListener("mousemove", function (e) { pts.push({ x: e.clientX, y: e.clientY, t: e.timeStamp }); });
  // speechSynthesis voices load asynchronously — kick the load early so the list is populated by the
  // time send() runs. The installed TTS voices are OS-specific (Microsoft → Windows, Apple → macOS,
  // espeak/eSpeak → Linux) and a real desktop has them; a headless container has none or Linux-only.
  var _voices = [];
  try {
    if (window.speechSynthesis) {
      var grab = function () { _voices = speechSynthesis.getVoices() || []; };
      grab();
      speechSynthesis.onvoiceschanged = grab;
    }
  } catch (e) {}
  function uaBrowser(ua) {
    if (/Firefox\\//.test(ua)) return "firefox";
    if (/Edg\\//.test(ua)) return "edge";
    if (/Chrome\\//.test(ua)) return "chrome";
    if (/Safari\\//.test(ua)) return "safari";
    return "unknown";
  }
  function uaPlatform(ua) {
    if (/Windows/.test(ua)) return "Windows";
    if (/Macintosh|Mac OS X/.test(ua)) return "macOS";
    if (/Android/.test(ua)) return "Android";
    if (/Linux/.test(ua)) return "Linux";
    return "unknown";
  }
  function canvasLie() {
    try { return !HTMLCanvasElement.prototype.toDataURL.toString().includes("[native code]"); }
    catch (e) { return true; }
  }
  function entropy(p) {
    if (p.length < 3) return 0;
    var b = [0,0,0,0,0,0,0,0], t = 0;
    for (var i = 1; i < p.length; i++) {
      var dx = p[i].x - p[i-1].x, dy = p[i].y - p[i-1].y;
      if (dx === 0 && dy === 0) continue;
      var a = Math.atan2(dy, dx), idx = Math.floor((a + Math.PI) / (2 * Math.PI) * 8);
      if (idx > 7) idx = 7; b[idx]++; t++;
    }
    if (t < 2) return 0;
    var h = 0;
    for (var j = 0; j < 8; j++) { if (b[j] > 0) { var pr = b[j] / t; h -= pr * Math.log2(pr); } }
    return h / Math.log2(8);
  }
  function d(a, c) { return Math.hypot(c.x - a.x, c.y - a.y); }
  function straightness(p) {
    if (p.length < 3) return 0;
    var tot = 0;
    for (var i = 1; i < p.length; i++) tot += d(p[i-1], p[i]);
    if (tot === 0) return 0;
    return d(p[0], p[p.length-1]) / tot;
  }
  function velcv(p) {
    var s = [];
    for (var i = 1; i < p.length; i++) { var dt = p[i].t - p[i-1].t; if (dt > 0) s.push(d(p[i-1], p[i]) / dt); }
    if (s.length < 2) return 1;
    var mean = s.reduce(function (a, b) { return a + b; }, 0) / s.length;
    if (mean === 0) return 1;
    var v = s.reduce(function (a, x) { return a + (x - mean) * (x - mean); }, 0) / s.length;
    return Math.sqrt(v) / mean;
  }
  function webglInfo() {
    try {
      var gl = document.createElement("canvas").getContext("webgl");
      if (!gl) return { vendor: "", renderer: "" };
      var ext = gl.getExtension("WEBGL_debug_renderer_info");
      return {
        vendor: ext ? String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || "") : "",
        renderer: ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || "") : "",
      };
    } catch (e) { return { vendor: "", renderer: "" }; }
  }
  function toStringTampered() {
    try {
      var fns = [Function.prototype.toString, HTMLCanvasElement.prototype.toDataURL,
                 navigator.permissions && navigator.permissions.query];
      for (var i = 0; i < fns.length; i++) {
        if (fns[i] && fns[i].toString().indexOf("[native code]") < 0) return true;
      }
      return false;
    } catch (e) { return true; }
  }
  async function permAnomaly() {
    try {
      if (!navigator.permissions || !window.Notification) return false;
      var st = (await navigator.permissions.query({ name: "notifications" })).state;
      return Notification.permission === "denied" && st !== "denied";
    } catch (e) { return false; }
  }
  // A Web Worker has its own navigator; main-thread-only spoofs (and some engine-level browsers)
  // diverge between the two — a tamper signal that survives coherent main-thread spoofing.
  function workerNav() {
    return new Promise(function (resolve) {
      try {
        var code = 'onmessage=function(){postMessage({ua:navigator.userAgent,' +
          'hw:navigator.hardwareConcurrency,plat:navigator.platform||"",' +
          'lang:(navigator.languages||[]).join(",")})}';
        var w = new Worker(URL.createObjectURL(new Blob([code], { type: "application/javascript" })));
        var t = setTimeout(function () { resolve(null); }, 1500);
        w.onmessage = function (e) { clearTimeout(t); resolve(e.data); w.terminate(); };
        w.postMessage(0);
      } catch (err) { resolve(null); }
    });
  }
  // Installed fonts betray the real OS: a box's font stack is OS-specific (Windows ships Segoe UI /
  // Calibri, macOS ships Lucida Grande / Menlo, Linux ships DejaVu / Liberation). An anti-detect
  // browser can spoof the UA platform but not cheaply re-skin the host's installed fonts — so the
  // detected font OS contradicting the claimed UA platform is a strong engine-agnostic OS-lie tell.
  function fontOSHint() {
    try {
      var bases = ["monospace", "sans-serif", "serif"], probe = "mmmmmmmmmmlli72px";
      var ctx = document.createElement("canvas").getContext("2d");
      function w(font) { ctx.font = "72px " + font; return ctx.measureText(probe).width; }
      var baseW = {}; bases.forEach(function (b) { baseW[b] = w(b); });
      function has(f) {
        for (var i = 0; i < bases.length; i++) {
          if (w("'" + f + "'," + bases[i]) !== baseW[bases[i]]) return true;
        }
        return false;
      }
      var groups = {
        Windows: ["Segoe UI", "Calibri", "Cambria", "Consolas", "Tahoma"],
        macOS: ["Helvetica Neue", "Lucida Grande", "Geneva", "Menlo", "Monaco"],
        Linux: ["DejaVu Sans", "Liberation Sans", "Ubuntu", "Cantarell", "Noto Sans"]
      };
      var best = "", bestN = 1; // require >= 2 signature fonts before classifying an OS
      Object.keys(groups).forEach(function (os) {
        var n = groups[os].filter(has).length;
        if (n > bestN) { bestN = n; best = os; }
      });
      return best;
    } catch (e) { return ""; }
  }
  async function send() {
    var ua = navigator.userAgent, now = new Date().toISOString();
    function S(layer, kind, value) {
      return { schema_version: "0.1", session_id: id, layer: layer, kind: kind, value: value, source: "collector", observed_at: now };
    }
    var sigs = [
      S("browser", "webdriver", navigator.webdriver === true),
      S("browser", "ua_browser", uaBrowser(ua)),
      S("browser", "ua_platform", uaPlatform(ua))
    ];
    var uad = navigator.userAgentData;
    if (uad && uad.platform) sigs.push(S("browser", "ch_platform", uad.platform));
    // navigator.platform implies an OS that must match the UA platform (engine-agnostic — works for
    // Firefox-based anti-detect too, where there is no Client-Hints platform).
    var np = navigator.platform || "";
    var npo = /Mac/i.test(np) ? "macOS" : /Win/i.test(np) ? "Windows"
            : /Linux|X11/i.test(np) ? "Linux" : /Android/i.test(np) ? "Android" : "";
    if (npo) sigs.push(S("browser", "nav_platform_os", npo));
    if (canvasLie()) sigs.push(S("browser", "canvas_lie", true));
    if (/Headless/i.test(ua)) sigs.push(S("browser", "ua_is_headless", true));
    // A genuine navigator.webdriver is inherited from Navigator.prototype; an own property means
    // it was patched via Object.defineProperty(navigator, ...).
    if (Object.getOwnPropertyDescriptor(navigator, "webdriver")) sigs.push(S("browser", "webdriver_spoofed", true));
    var wg = webglInfo();
    if (wg.renderer) sigs.push(S("browser", "webgl_renderer", wg.renderer));
    if (wg.vendor) sigs.push(S("browser", "webgl_vendor", wg.vendor));
    if (/swiftshader|llvmpipe|software|mesa/i.test(wg.renderer)) sigs.push(S("browser", "webgl_software", true));
    // The GPU API in the renderer string implies an OS (Direct3D=Windows, Metal=macOS) — a spoofed
    // renderer often contradicts the platform (e.g. a Direct3D GPU on Linux).
    var wo = /Direct3D|D3D[0-9]/i.test(wg.renderer) ? "Windows"
           : /Metal|Apple/i.test(wg.renderer) ? "macOS"
           : /Vulkan|OpenGL|GLX|Mesa|SwiftShader|llvmpipe/i.test(wg.renderer) ? "Linux" : "";
    if (wo) sigs.push(S("browser", "webgl_os_hint", wo));
    if (/Chrome|Edg/.test(ua) && !window.chrome) sigs.push(S("browser", "chrome_object_missing", true));
    if (toStringTampered()) sigs.push(S("browser", "function_tostring_tampered", true));
    try {
      if (WebGLRenderingContext.prototype.getParameter.toString().indexOf("[native code]") < 0)
        sigs.push(S("browser", "webgl_getparameter_tampered", true));
    } catch (e) {}
    if (Object.getOwnPropertyDescriptor(navigator, "plugins")) sigs.push(S("browser", "plugins_spoofed", true));
    try {
      var wd = Object.getOwnPropertyDescriptor(Navigator.prototype, "webdriver");
      if (wd && wd.get && wd.get.toString().indexOf("[native code]") < 0)
        sigs.push(S("browser", "webdriver_getter_tampered", true));
    } catch (e) {}
    sigs.push(S("browser", "hardware_concurrency", navigator.hardwareConcurrency || 0));
    sigs.push(S("browser", "plugins_count", (navigator.plugins && navigator.plugins.length) || 0));
    if (await permAnomaly()) sigs.push(S("browser", "permissions_anomaly", true));
    // --- v0.9.0 bulk fingerprint + coherence checks (CreepJS / Sannysoft / fpscanner) ---
    var uaEngine = /Firefox\\//.test(ua) ? "firefox"
                 : /Edg\\/|Chrome\\//.test(ua) ? "chromium"
                 : /Safari\\//.test(ua) ? "safari" : "other";
    sigs.push(S("browser", "ua_engine", uaEngine));
    var ven = navigator.vendor;
    var venEngine = /Google/i.test(ven) ? "chromium" : ven === "" ? "firefox"
                  : /Apple/i.test(ven) ? "safari" : "other";
    sigs.push(S("browser", "vendor_engine", venEngine));
    if (navigator.oscpu) {
      var oc = /Mac/i.test(navigator.oscpu) ? "macOS" : /Win/i.test(navigator.oscpu) ? "Windows"
             : /Linux/i.test(navigator.oscpu) ? "Linux" : "";
      if (oc) sigs.push(S("browser", "oscpu_os", oc));
    }
    var isChromium = uaEngine === "chromium";
    if (!navigator.languages || navigator.languages.length === 0) sigs.push(S("browser", "languages_empty", true));
    if (!screen.width || !screen.height || window.outerWidth === 0 || window.outerHeight === 0) sigs.push(S("browser", "screen_zero", true));
    if (isChromium && !navigator.connection) sigs.push(S("browser", "chrome_no_connection", true));
    if (isChromium && navigator.pdfViewerEnabled === false) sigs.push(S("browser", "chrome_no_pdfviewer", true));
    if (window.chrome && !window.chrome.runtime) sigs.push(S("browser", "chrome_runtime_missing", true));
    if (navigator.maxTouchPoints > 0 && !/Mobile|Android|iPhone|iPad/i.test(ua)) sigs.push(S("browser", "maxtouch_desktop", true));
    if (navigator.mimeTypes && navigator.mimeTypes.length === 0) sigs.push(S("browser", "mimetypes_empty", true));
    if (isChromium && typeof navigator.deviceMemory === "undefined") sigs.push(S("browser", "chrome_no_devicememory", true));
    try { if (window.Notification && Notification.permission === "denied") sigs.push(S("browser", "notification_denied", true)); } catch (e) {}
    // --- v0.10.0 wave: more lie-detection (CreepJS / Sannysoft / fpscanner) ---
    if (navigator.platform === "") sigs.push(S("browser", "platform_empty", true));
    var uaRender = uaEngine === "firefox" ? "gecko" : "webkit";
    sigs.push(S("browser", "ua_render", uaRender));
    var ps = navigator.productSub === "20030107" ? "webkit"
           : navigator.productSub === "20100101" ? "gecko" : "";
    if (ps) sigs.push(S("browser", "productsub_render", ps));
    var cdcKeys = ["$cdc_asdjflasutopfhvcZLmcfl_", "__webdriver_evaluate", "__selenium_evaluate",
      "__webdriver_script_fn", "_Selenium_IDE_Recorder", "_phantom", "callPhantom", "__nightmare",
      "domAutomation", "__driver_evaluate"];
    if (cdcKeys.some(function (k) { return k in window || k in document; })) sigs.push(S("browser", "cdc_artifacts", true));
    try { if (!document.createElement("canvas").getContext("webgl2")) sigs.push(S("browser", "webgl2_missing", true)); } catch (e) {}
    // --- v0.11.0 wave: installed-font OS fingerprint (the engine-level OS-lie counter) ---
    var fo = fontOSHint();
    if (fo) sigs.push(S("browser", "font_os_hint", fo));
    // --- v0.12.0 wave: cross-API device/media coherence (CreepJS / fingerprintjs) ---
    // The CSS view of the device (matchMedia) and the JS-API view (navigator/screen) must agree; a
    // spoof that patches one surface but not the other is incoherent across them.
    try {
      // availWidth/Height can never exceed the physical screen — a spoofed screen object often slips.
      if (screen.availWidth > screen.width || screen.availHeight > screen.height)
        sigs.push(S("browser", "screen_avail_invalid", true));
      // Real displays report 24/30/32-bit colour; 0/16 is a headless/software artifact.
      if (screen.colorDepth && [24, 30, 32].indexOf(screen.colorDepth) < 0)
        sigs.push(S("browser", "color_depth_anomaly", true));
      // devicePixelRatio must be a positive finite number; <= 0 / NaN is a spoof/headless tell.
      if (!(window.devicePixelRatio > 0)) sigs.push(S("browser", "devicepixelratio_anomaly", true));
      // A non-mobile UA that reports no hover capability contradicts a real desktop pointer.
      var isMobile = /Mobile|Android|iPhone|iPad/i.test(ua);
      if (!isMobile && window.matchMedia && matchMedia("(hover: none)").matches)
        sigs.push(S("browser", "hover_none_desktop", true));
      // CSS coarse-pointer (touch) and navigator.maxTouchPoints describe the same capability; if the
      // CSS surface says touch but the JS surface says none (or vice-versa) the device is incoherent.
      if (window.matchMedia) {
        var cssTouch = matchMedia("(any-pointer: coarse)").matches;
        var jsTouch = (navigator.maxTouchPoints || 0) > 0;
        if (cssTouch !== jsTouch) sigs.push(S("browser", "pointer_touch_incoherent", true));
      }
    } catch (e) {}
    // --- v0.13.0 wave: speech-synthesis voice coherence (OS-specific TTS, hard to spoof) ---
    try {
      if (window.speechSynthesis) {
        if (_voices.length === 0) {
          sigs.push(S("browser", "voices_empty", true));  // no OS TTS — headless/container tell
        } else {
          var names = _voices.map(function (v) { return (v.name || "") + " " + (v.voiceURI || ""); }).join(" ");
          var voiceOS = /Microsoft|Windows|David|Zira|Hazel/i.test(names) ? "Windows"
                      : /Apple|Siri|Alex|Samantha|Victoria|macOS/i.test(names) ? "macOS"
                      : /espeak|eSpeak|Linux/i.test(names) ? "Linux" : "";
          if (voiceOS) sigs.push(S("browser", "voice_os_hint", voiceOS));
        }
      }
    } catch (e) {}
    try {
      var ifr = document.createElement("iframe");
      ifr.style.display = "none"; document.body.appendChild(ifr);
      if (ifr.contentWindow.navigator.userAgent !== navigator.userAgent) sigs.push(S("browser", "iframe_divergence", true));
      document.body.removeChild(ifr);
    } catch (e) {}
    var wn = await workerNav();
    if (wn && (wn.ua !== navigator.userAgent || wn.hw !== navigator.hardwareConcurrency ||
        (wn.plat && navigator.platform && wn.plat !== navigator.platform))) {
      sigs.push(S("browser", "worker_divergence", true));
    }
    // In `?fast` (detection-only) captures we don't simulate input, so emitting empty behavioral
    // signals would make the *absence* of input score as bot-like and mask the fingerprint result.
    // Omit the behavioral layer entirely in fast mode; a full capture still scores behaviour.
    if (!/(?:\\?|&)fast\\b/.test(location.search)) {
      sigs.push(S("behavioral", "mouse_entropy", entropy(pts)));
      sigs.push(S("behavioral", "pointer_event_count", pts.length));
      if (pts.length >= 3) {
        sigs.push(S("behavioral", "mouse_straightness", straightness(pts)));
        sigs.push(S("behavioral", "mouse_velocity_cv", velcv(pts)));
      }
    }
    fetch("/ingest", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sigs) })
      .then(function () { document.body.setAttribute("data-ks", "sent"); });
  }
  // Default 1200ms lets behavioral (mouse) signals accumulate. `?fast` cuts the wait for
  // detection-only captures that need the browser-layer fingerprint, not behaviour (e.g. the
  // single-Camoufox frontier test); body[data-ks=sent] lets a harness wait on completion.
  setTimeout(function () { send(); }, /(?:\\?|&)fast\\b/.test(location.search) ? 200 : 1200);
})();
</script></body></html>
"""
