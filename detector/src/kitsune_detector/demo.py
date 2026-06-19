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
  // Coalesced pointer events: real hardware movement is sampled faster than the browser dispatches
  // events, so getCoalescedEvents() batches the intermediate samples (length > 1). Synthetic movement
  // injected via CDP (Input.dispatchMouseEvent — how Playwright/Puppeteer/driverless tools fake a
  // human-like curved path) arrives one discrete event at a time and never coalesces. A long pointer
  // stream that never coalesces, on an engine that supports it, is an injected-input tell that survives
  // even a bot which has defeated the path-straightness and velocity behavioral checks.
  var ptrMoves = 0, coalescedMax = 0;
  var coalescedSupported = typeof PointerEvent !== "undefined" && "getCoalescedEvents" in PointerEvent.prototype;
  if (coalescedSupported) {
    addEventListener("pointermove", function (e) {
      ptrMoves++;
      try { var c = e.getCoalescedEvents(); if (c && c.length > coalescedMax) coalescedMax = c.length; } catch (err) {}
    });
  }
  // Keystroke timing: a real typist has variable inter-key intervals (digraph latencies differ); a script
  // that types at a fixed delay has near-zero interval entropy — the keystroke-dynamics tell.
  var keys = [];
  addEventListener("keydown", function (e) { keys.push(e.timeStamp); });
  // CSP-bypass probe: the page is served with `img-src 'none'`, so loading any image violates the
  // policy and fires securitypolicyviolation in a real browser. Playwright/Puppeteer scrapers that call
  // setBypassCSP(true) to inject their scripts silently disable enforcement, so the violation never
  // fires — an automation tell rebrowser-patches explicitly cannot fix. The listener is attached before
  // the probe is triggered, so there is no ordering race (a violation can only occur after this point).
  var cspEnforced = false;
  addEventListener("securitypolicyviolation", function () { cspEnforced = true; });
  try {
    var _csp = new Image();
    _csp.src = "data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==";
  } catch (e) {}
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
  // Adblock "bait" element, added early so a content blocker's cosmetic filters have time to hide it by
  // send(). Camoufox ships uBlock Origin as a *default* addon (per its source), so a stock Camoufox hides
  // this — a corroborating tell (weak alone: many humans run adblockers too).
  var _bait = null;
  try {
    _bait = document.createElement("div");
    _bait.className = "adsbox ad-banner pub_300x250 text-ad sponsored doubleclick";
    _bait.style.cssText = "position:absolute;left:-9999px;top:-9999px;height:12px;width:12px;";
    _bait.innerHTML = "&nbsp;";
    addEventListener("DOMContentLoaded", function () { try { document.body.appendChild(_bait); } catch (e) {} });
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
  // CDP Runtime.enable leak (the current #1 headless-Chromium automation tell). Playwright/Puppeteer
  // enable the CDP Runtime domain, which *eagerly serializes* console arguments for the inspector —
  // accessing Error.stack. A normal browser with no CDP client attached never reads it. rebrowser-patches
  // exists specifically to defeat this. Ref: "How V8 Leaks Your Headless Browser's Identity" (2024-25).
  function cdpRuntimeEnabled() {
    try {
      var detected = false;
      var e = new Error();
      Object.defineProperty(e, "stack", {
        configurable: false, enumerable: false,
        get: function () { detected = true; return ""; }
      });
      console.debug(e);  // captured + serialized by CDP Runtime.enable; the getter fires only then
      return detected;
    } catch (err) { return false; }
  }
  // AudioContext fingerprint via OfflineAudioContext (pure computation — works headless). A real engine
  // is deterministic: rendering the same graph twice yields the identical sum. Anti-detect / farbling
  // browsers inject per-render noise to defeat fingerprinting, so the two renders differ — itself a tell.
  function audioFP() {
    return new Promise(function (resolve) {
      try {
        var OAC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (!OAC) { resolve({ missing: true }); return; }
        function render(cb) {
          var ctx = new OAC(1, 4410, 44100);
          var osc = ctx.createOscillator();
          osc.type = "triangle"; osc.frequency.value = 10000;
          var comp = ctx.createDynamicsCompressor();
          comp.threshold.value = -50; comp.knee.value = 40; comp.ratio.value = 12;
          comp.attack.value = 0; comp.release.value = 0.25;
          osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
          ctx.startRendering().then(function (buf) {
            var data = buf.getChannelData(0), sum = 0;
            for (var i = 0; i < data.length; i++) sum += Math.abs(data[i]);
            cb(sum);
          }).catch(function () { cb(null); });
        }
        render(function (a) {
          if (a === null) { resolve({ missing: true }); return; }
          render(function (b) { resolve({ missing: false, noise: a !== b, value: a }); });
        });
      } catch (e) { resolve({ missing: true }); }
    });
  }
  // WebRTC ICE-candidate probe. A real browser gathers candidates (host/mDNS, and a STUN srflx = its
  // public IP). The public IP that leaks here is the *true* network identity — for a proxied bot it
  // contradicts the request IP (a cross-layer tell). Total unavailability is itself anomalous: some
  // anti-detect tools disable WebRTC to avoid the IP leak, which a normal browser never does.
  function webrtcProbe() {
    return new Promise(function (resolve) {
      var host = {}, pub = null, any = false, done = false;
      function finish(unavailable) {
        if (done) return; done = true;
        resolve({ hostCount: Object.keys(host).length, pub: pub, any: any, unavailable: !!unavailable });
      }
      try {
        var RPC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
        if (!RPC) { finish(true); return; }
        var pc = new RPC({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
        pc.createDataChannel("ks");
        pc.onicecandidate = function (e) {
          if (!e || !e.candidate) { try { pc.close(); } catch (x) {} finish(false); return; }
          any = true;
          var c = e.candidate.candidate, m = c.match(/([0-9]{1,3}(?:\\.[0-9]{1,3}){3})/);
          if (m) { if (/ typ srflx /.test(c)) pub = m[1]; else if (/ typ host /.test(c)) host[m[1]] = 1; }
        };
        pc.createOffer().then(function (o) { return pc.setLocalDescription(o); }).catch(function () {});
        // 700ms: local host/mDNS candidates arrive in ~200ms; a STUN srflx that is reachable comes soon
        // after. Keeps the collector's total budget bounded so fixed-wait evaders capture before closing.
        setTimeout(function () { try { pc.close(); } catch (x) {} finish(false); }, 700);
      } catch (e) { finish(true); }
    });
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
  // Normalized Shannon entropy of inter-keystroke intervals (log-bucketed). Human typing spreads across
  // many latency buckets (~high); a fixed-delay script collapses to one bucket (~0).
  function keyEntropy(ks) {
    if (ks.length < 4) return 1; // too few keystrokes to judge — don't flag
    var b = {}, t = 0;
    for (var i = 1; i < ks.length; i++) {
      var dt = ks[i] - ks[i - 1];
      if (dt <= 0) continue;
      var bucket = Math.round(Math.log2(dt) * 2); // ~half-octave buckets
      b[bucket] = (b[bucket] || 0) + 1; t++;
    }
    if (t < 3) return 1;
    var h = 0, n = 0;
    for (var k in b) { if (b.hasOwnProperty(k)) { var pr = b[k] / t; h -= pr * Math.log2(pr); n++; } }
    return n <= 1 ? 0 : h / Math.log2(n);
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
  // Stable hash of the pointer trajectory shape (quantised coords; timing excluded). Two real users never
  // trace the same path, so an identical trace_hash across distinct IPs is a replayed canned trajectory —
  // the behavioural analog of fp_hash (the coordination scorer reads it). Null below a movement floor.
  function traceHash(p) {
    if (p.length < 12) return null;
    var h = 2166136261;
    function mix(n) { h = ((h ^ (n & 0xffff)) * 16777619) >>> 0; }
    for (var i = 0; i < p.length; i++) { mix(Math.round(p[i].x)); mix(Math.round(p[i].y)); }
    return (h >>> 0).toString(16);
  }
  // --- biomechanics (mirror of kitsune_harness.biomech; calibrated vs Balabit, see docs/behavioral-data.md) ---
  function speeds(p) {
    var s = [];
    for (var i = 1; i < p.length; i++) { var dt = p[i].t - p[i-1].t; if (dt > 0) s.push(d(p[i-1], p[i]) / dt); }
    return s;
  }
  function submovementCount(p) {
    var s = speeds(p);
    if (s.length < 3) return 0;
    var mx = Math.max.apply(null, s), floor = mx * 0.1, n = 0;
    for (var i = 1; i < s.length - 1; i++) if (s[i] > floor && s[i] >= s[i-1] && s[i] > s[i+1]) n++;
    return n;
  }
  function pauseRatio(p) {
    var s = speeds(p);
    if (!s.length) return 0;
    var mx = Math.max.apply(null, s), th = mx * 0.05, n = 0;
    for (var i = 0; i < s.length; i++) if (s[i] <= th) n++;
    return n / s.length;
  }
  function powerLawExp(p) {
    // β in V ∝ R^β over curved interior points (Menger curvature + log-log OLS); null if <3 fittable points.
    var xs = [], ys = [];
    for (var i = 0; i < p.length - 2; i++) {
      var a = p[i], b = p[i+1], c = p[i+2];
      var ab = d(a, b), bc = d(b, c), ca = d(c, a), dt = c.t - a.t;
      if (ab === 0 || bc === 0 || ca === 0 || dt <= 0) continue;
      var area2 = Math.abs((b.x-a.x)*(c.y-a.y) - (c.x-a.x)*(b.y-a.y));
      var kappa = 2 * area2 / (ab * bc * ca);
      if (kappa <= 0) continue;
      var v = ca / dt, r = 1 / kappa;
      if (v > 0 && r > 0) { xs.push(Math.log(r)); ys.push(Math.log(v)); }
    }
    if (xs.length < 3) return null;
    var n = xs.length, mx = 0, my = 0, j;
    for (j = 0; j < n; j++) { mx += xs[j]; my += ys[j]; }
    mx /= n; my /= n;
    var sxx = 0, sxy = 0;
    for (j = 0; j < n; j++) { sxx += (xs[j]-mx)*(xs[j]-mx); sxy += (xs[j]-mx)*(ys[j]-my); }
    if (sxx === 0) return null;
    return sxy / sxx;
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
      // getVoices/enumerateDevices included so a tool faking the environment floor (spoofing voices or
      // media devices to beat voices_empty/media_devices_empty) is caught by the override's non-native
      // toString — a real browser never replaces these. See the FLOOR_SPOOF evader.
      var fns = [Function.prototype.toString, HTMLCanvasElement.prototype.toDataURL,
                 HTMLCanvasElement.prototype.toBlob,
                 CanvasRenderingContext2D.prototype.getImageData,
                 navigator.permissions && navigator.permissions.query,
                 window.speechSynthesis && speechSynthesis.getVoices,
                 navigator.mediaDevices && navigator.mediaDevices.enumerateDevices];
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
  // The WebGL UNMASKED_RENDERER from an OffscreenCanvas inside a Worker. A getParameter spoof patches the
  // main realm but not Worker scope, so a Worker reports the real GPU. Null on any failure → never fires.
  function workerGlRenderer() {
    return new Promise(function (resolve) {
      try {
        var code = 'onmessage=function(){try{' +
          "var c=new OffscreenCanvas(8,8);var gl=c.getContext('webgl');" +
          "var d=gl&&gl.getExtension('WEBGL_debug_renderer_info');" +
          'postMessage(d?String(gl.getParameter(d.UNMASKED_RENDERER_WEBGL)):null);' +
          '}catch(e){postMessage(null);}}';
        var w = new Worker(URL.createObjectURL(new Blob([code], { type: "application/javascript" })));
        var t = setTimeout(function () { resolve(null); }, 1500);
        w.onmessage = function (e) { clearTimeout(t); resolve(e.data); w.terminate(); };
        w.postMessage(0);
      } catch (err) { resolve(null); }
    });
  }
  // Canvas realm coherence: identical 2D draw ops must hash the same on the main canvas and a Worker
  // OffscreenCanvas. CW_DRAW (worker string) and mainCanvasHashCW's inline ops must stay byte-identical.
  var CW_DRAW = "ctx.textBaseline='top';ctx.font='14px sans-serif';" +
    "ctx.fillStyle='#069';ctx.fillRect(0,0,100,40);" +
    "ctx.fillStyle='#f60';ctx.fillText('Kitsune-CW-7',2,2);" +
    "ctx.strokeStyle='rgba(0,128,0,0.7)';ctx.beginPath();ctx.arc(40,20,15,0,7);ctx.stroke();";
  function cwHash(d) { var h = 2166136261; for (var i = 0; i < d.length; i += 97) { h = ((h ^ (d[i] || 0)) * 16777619) >>> 0; } return h; }
  function mainCanvasHashCW() {
    try {
      var c = document.createElement("canvas"); c.width = 100; c.height = 40;
      var ctx = c.getContext("2d"); if (!ctx) return null;
      ctx.textBaseline = "top"; ctx.font = "14px sans-serif";
      ctx.fillStyle = "#069"; ctx.fillRect(0, 0, 100, 40);
      ctx.fillStyle = "#f60"; ctx.fillText("Kitsune-CW-7", 2, 2);
      ctx.strokeStyle = "rgba(0,128,0,0.7)"; ctx.beginPath(); ctx.arc(40, 20, 15, 0, 7); ctx.stroke();
      return cwHash(ctx.getImageData(0, 0, 100, 40).data);
    } catch (e) { return null; }
  }
  function workerCanvasHashCW() {
    return new Promise(function (resolve) {
      try {
        var code = "var H=function(d){var h=2166136261;for(var i=0;i<d.length;i+=97){h=((h^(d[i]||0))*16777619)>>>0;}return h;};" +
          "onmessage=function(){try{var c=new OffscreenCanvas(100,40);var ctx=c.getContext('2d');" +
          CW_DRAW + "postMessage(H(ctx.getImageData(0,0,100,40).data));}catch(e){postMessage(null);}}";
        var w = new Worker(URL.createObjectURL(new Blob([code], { type: "application/javascript" })));
        var t = setTimeout(function () { resolve(null); }, 1500);
        w.onmessage = function (e) { clearTimeout(t); resolve(e.data); w.terminate(); };
        w.postMessage(0);
      } catch (err) { resolve(null); }
    });
  }
  // Timezone reported inside a Worker — a process-level setting identical across realms on a real browser
  // (and a legit CDP override); only a JS main-realm geo-spoof fails to reach Worker scope.
  function workerTz() {
    return new Promise(function (resolve) {
      try {
        var code = "onmessage=function(){var tz='';try{tz=Intl.DateTimeFormat().resolvedOptions().timeZone||'';}catch(e){}" +
          "postMessage({tz:tz,off:new Date().getTimezoneOffset()});}";
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
  // Is a single named font installed? (width differs from a generic fallback in any base family.)
  function fontPresent(f) {
    try {
      var bases = ["monospace", "sans-serif", "serif"], probe = "mmmmmmmmmmlli72px";
      var ctx = document.createElement("canvas").getContext("2d");
      function w(font) { ctx.font = "72px " + font; return ctx.measureText(probe).width; }
      for (var i = 0; i < bases.length; i++) {
        if (w("'" + f + "'," + bases[i]) !== w(bases[i])) return true;
      }
      return false;
    } catch (e) { return false; }
  }
  async function send() {
    var ua = navigator.userAgent, now = new Date().toISOString();
    function S(layer, kind, value) {
      return { schema_version: "0.1", session_id: id, layer: layer, kind: kind, value: value, source: "collector", observed_at: now };
    }
    var plat = uaPlatform(ua);
    // Android IS Linux: its navigator.platform / oscpu / WebGL report the Linux kernel ("Linux armv8l",
    // OpenGL ES), which under an Android UA is the genuine value, not a spoof. Resolve such a "Linux" hint
    // to the device's true OS family ("Android") so the platform-coherence rules don't false-fire on every
    // real Android visitor (Intoli real-traffic: 73% of legit sessions). Desktop OS spoofs are untouched.
    function osForUa(os) { return (plat === "Android" && os === "Linux") ? "Android" : os; }
    var sigs = [
      S("browser", "webdriver", navigator.webdriver === true),
      S("browser", "ua_browser", uaBrowser(ua)),
      S("browser", "ua_platform", plat)
    ];
    var uad = navigator.userAgentData;
    if (uad && uad.platform) sigs.push(S("browser", "ch_platform", uad.platform));
    // UA-Client-Hints HIGH-entropy coherence. getHighEntropyValues is Chromium-only and needs a secure
    // context (the edge serves HTTPS); it is a surface UA-string spoofers routinely forget to patch.
    // (a) the high-entropy brand list still names HeadlessChrome even when the UA string was cleaned —
    // a headless tell deeper than ua_is_headless; (b) its Chrome version must match the UA-string version.
    if (uad && uad.getHighEntropyValues) {
      try {
        var he = await uad.getHighEntropyValues(["uaFullVersion", "fullVersionList"]);
        var fvl = he.fullVersionList || [];
        var brandList = fvl.concat(uad.brands || []);
        if (brandList.some(function (b) { return /headless/i.test((b && b.brand) || ""); }))
          sigs.push(S("browser", "ch_he_headless", true));
        var chBrand = fvl.filter(function (b) { return /chrom/i.test((b && b.brand) || ""); })[0];
        var chMajor = (chBrand ? String(chBrand.version || "") : String(he.uaFullVersion || "")).split(".")[0];
        var uaM = (ua.match(/Chrome\\/(\\d+)/) || [])[1];
        if (chMajor && uaM && chMajor !== uaM) sigs.push(S("browser", "ch_he_version_vs_ua", true));
      } catch (e) {}
    }
    // navigator.platform implies an OS that must match the UA platform (engine-agnostic — works for
    // Firefox-based anti-detect too, where there is no Client-Hints platform).
    var np = navigator.platform || "";
    var npo = /Mac/i.test(np) ? "macOS" : /Win/i.test(np) ? "Windows"
            : /Linux|X11/i.test(np) ? "Linux" : /Android/i.test(np) ? "Android" : "";
    npo = osForUa(npo);
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
    // Anti-detect renderer-spoofing artifacts: real GPU driver strings are exact. Camoufox labels its
    // randomized GPU pick with ", or similar"; placeholder/vague renderers never come from real drivers.
    if (/,\\s*or similar|generic renderer|placeholder/i.test(wg.renderer)) sigs.push(S("browser", "webgl_renderer_artifact", true));
    // The GPU API in the renderer string implies an OS (Direct3D=Windows, Metal=macOS) — a spoofed
    // renderer often contradicts the platform (e.g. a Direct3D GPU on Linux).
    var wo = /Direct3D|D3D[0-9]/i.test(wg.renderer) ? "Windows"
           : /Metal|Apple/i.test(wg.renderer) ? "macOS"
           : /Vulkan|OpenGL|GLX|Mesa|SwiftShader|llvmpipe/i.test(wg.renderer) ? "Linux" : "";
    wo = osForUa(wo);
    if (wo) sigs.push(S("browser", "webgl_os_hint", wo));
    if (/Chrome|Edg/.test(ua) && !window.chrome) sigs.push(S("browser", "chrome_object_missing", true));
    if (toStringTampered()) sigs.push(S("browser", "function_tostring_tampered", true));
    // Native-function invariant check (deeper than function_tostring_tampered): a real built-in method is
    // NOT a constructor (`new fn()` throws) and has no own `prototype` property. A Proxy/wrapper spoof can
    // fake the "[native code]" toString yet violate these invariants. Only flag methods that CLAIM native.
    try {
      var natives = [navigator.permissions && navigator.permissions.query,
                     HTMLCanvasElement.prototype.toDataURL,
                     navigator.mediaDevices && navigator.mediaDevices.enumerateDevices,
                     WebGLRenderingContext.prototype.getParameter, Function.prototype.bind];
      for (var ni = 0; ni < natives.length; ni++) {
        var fn = natives[ni];
        if (typeof fn !== "function" || fn.toString().indexOf("[native code]") < 0) continue;
        if (Object.prototype.hasOwnProperty.call(fn, "prototype")) { sigs.push(S("browser", "native_invariant_violated", true)); break; }
        var ctor = false; try { new fn(); ctor = true; } catch (e) {}
        if (ctor) { sigs.push(S("browser", "native_invariant_violated", true)); break; }
      }
    } catch (e) {}
    // Worker-realm constructor integrity: a tool can only defeat the realm-coherence rules (worker/
    // timezone/languages/webgl/canvas_worker_vs_main) by wrapping window.Worker / OffscreenCanvas to inject
    // its spoof into worker scope — but a real browser's global Worker/OffscreenCanvas are native; a
    // wrapped one's toString lacks "[native code]". Closes the escalation path for the whole family.
    try {
      function ctorTampered(c) { return typeof c === "function" && c.toString().indexOf("[native code]") < 0; }
      if (ctorTampered(self.Worker) || ctorTampered(self.OffscreenCanvas)) {
        sigs.push(S("browser", "worker_constructor_tampered", true));
      }
    } catch (e) {}
    // Electron process leak: a renderer exposing a Node `process` (type=renderer or versions.electron) is
    // an Electron/automation runtime, never a real browser. Guarded to the Electron-specific markers so a
    // webpack `process.env` shim does not trip it.
    try {
      if (typeof process !== "undefined" && process &&
          ((process.versions && process.versions.electron) || process.type === "renderer"))
        sigs.push(S("browser", "electron_process", true));
    } catch (e) {}
    // DOMRect invariants: on a real engine getBoundingClientRect is deterministic (two reads of an
    // unchanged element are identical) and a single-rect element's getClientRects()[0] equals it. A
    // per-call DOMRect-noise shim breaks determinism; a tool that hooks one geometry path but not the
    // other breaks consistency. Verified deterministic + consistent on real Chrome.
    try {
      var dre = document.createElement("div");
      dre.style.cssText = "position:absolute;left:-9999px;top:0;width:123.45px;height:67.8px;transform:rotate(7deg) scale(1.3)";
      dre.textContent = "x";
      document.documentElement.appendChild(dre);
      var dra = dre.getBoundingClientRect(), drc = dre.getBoundingClientRect();
      var drDet = dra.x === drc.x && dra.y === drc.y && dra.width === drc.width && dra.height === drc.height;
      var drRects = dre.getClientRects(), dr0 = drRects[0];
      var drCons = drRects.length === 1 && dr0 &&
        Math.abs(dr0.width - dra.width) < 1e-6 && Math.abs(dr0.height - dra.height) < 1e-6 &&
        Math.abs(dr0.x - dra.x) < 1e-6 && Math.abs(dr0.y - dra.y) < 1e-6;
      document.documentElement.removeChild(dre);
      if (!drDet || !drCons) sigs.push(S("browser", "domrect_invariant_violated", true));
    } catch (e) {}
    // measureText main-vs-OffscreenCanvas coherence: both use the same engine font metrics, so on a real
    // browser they are identical (verified width 390.34375 == on Chrome). A tool that hooks main-thread
    // CanvasRenderingContext2D.measureText to spoof fonts (e.g. Camoufox) but not the OffscreenCanvas path
    // diverges — an incomplete-spoof tell a real browser never trips.
    try {
      if (typeof OffscreenCanvas !== "undefined") {
        var mtProbe = "mmMwWLil10Oo gjpqy 文字", mtFont = "16px sans-serif";
        var mtMain = document.createElement("canvas").getContext("2d"); mtMain.font = mtFont;
        var mtOff = new OffscreenCanvas(300, 80).getContext("2d"); mtOff.font = mtFont;
        var m1 = mtMain.measureText(mtProbe), m2 = mtOff.measureText(mtProbe);
        if (m1.width !== m2.width || m1.actualBoundingBoxAscent !== m2.actualBoundingBoxAscent)
          sigs.push(S("browser", "measuretext_offscreen_divergence", true));
      }
    } catch (e) {}
    try {
      if (WebGLRenderingContext.prototype.getParameter.toString().indexOf("[native code]") < 0)
        sigs.push(S("browser", "webgl_getparameter_tampered", true));
    } catch (e) {}
    if (Object.getOwnPropertyDescriptor(navigator, "plugins")) sigs.push(S("browser", "plugins_spoofed", true));
    // The same own-property lie, generalised: pdfViewerEnabled and mimeTypes are prototype-inherited on a
    // real Navigator, so an own property on the instance means a tool redefined them to fake the PDF floor
    // (beating chrome_no_pdfviewer / mimetypes_empty). See the FLOOR_SPOOF evader.
    try {
      var spoofed = ["pdfViewerEnabled", "mimeTypes"];
      for (var si = 0; si < spoofed.length; si++) {
        if (Object.getOwnPropertyDescriptor(navigator, spoofed[si])) {
          sigs.push(S("browser", "nav_property_spoofed", true));
          break;
        }
      }
    } catch (e) {}
    try {
      var wd = Object.getOwnPropertyDescriptor(Navigator.prototype, "webdriver");
      if (wd && wd.get && wd.get.toString().indexOf("[native code]") < 0)
        sigs.push(S("browser", "webdriver_getter_tampered", true));
    } catch (e) {}
    // Notification.permission is a native static getter. A tool that fakes it (e.g. claiming "default" to
    // beat notification_denied — and so coincidentally matching the headless Permissions API "prompt"
    // state, defeating permissions_anomaly too) leaves a non-native getter: the override is the only tell.
    try {
      if (window.Notification) {
        var npd = Object.getOwnPropertyDescriptor(Notification, "permission");
        if (npd && npd.get && npd.get.toString().indexOf("[native code]") < 0)
          sigs.push(S("browser", "notification_getter_tampered", true));
      }
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
    // Error.captureStackTrace is a V8 (Chromium) API; SpiderMonkey (Firefox) and JSC (Safari) lack it.
    // A UA claiming Chrome without it — or claiming Firefox WITH it — is an engine spoof deeper than
    // navigator.vendor (which JS-stealth tools patch, while the Error constructor's API they often miss).
    var hasV8Stack = typeof Error.captureStackTrace === "function";
    if ((uaEngine === "chromium" && !hasV8Stack) || (uaEngine === "firefox" && hasV8Stack))
      sigs.push(S("browser", "engine_stack_mismatch", true));
    // Engine error-message format — deeper than navigator.vendor or Error.captureStackTrace, because it
    // is the engine's own message generator (which JS-stealth tools do not rewrite). The same error reads
    // differently per engine: V8 "Cannot read properties of…", SpiderMonkey "can't access property…",
    // JSC "… is not an object". A message format that contradicts the claimed UA engine is a spoof.
    try {
      var _u; _u.x;  // throws TypeError
    } catch (errProbe) {
      var em = errProbe.message || "";
      var errEngine = /Cannot read propert/.test(em) ? "chromium"
                    : /can't access propert|has no propert/i.test(em) ? "firefox"
                    : /is not an object/.test(em) ? "safari" : "";
      if (errEngine && uaEngine !== "other" && errEngine !== uaEngine)
        sigs.push(S("browser", "error_engine_mismatch", true));
    }
    // Engine float-precision tell (CreepJS Math fingerprint): Math.pow(PI,-100) differs by the last ULP
    // between V8 (...204e-50) and SpiderMonkey (...206e-50) — the engine's own pow implementation, stable
    // across OS/version (verified V8 vs Firefox). A hard-to-spoof channel: a UA-spoofer that patches the
    // obvious engine tells rarely also matches the right engine's float precision.
    try {
      var mp = Math.pow(Math.PI, -100).toString();
      var mathEngine = mp === "1.9275814160560204e-50" ? "chromium"
                     : mp === "1.9275814160560206e-50" ? "firefox" : "";
      if (mathEngine && uaEngine !== "other" && mathEngine !== uaEngine)
        sigs.push(S("browser", "math_engine_mismatch", true));
    } catch (e) {}
    if (navigator.oscpu) {
      var oc = /Mac/i.test(navigator.oscpu) ? "macOS" : /Win/i.test(navigator.oscpu) ? "Windows"
             : /Linux/i.test(navigator.oscpu) ? "Linux" : "";
      oc = osForUa(oc);
      if (oc) sigs.push(S("browser", "oscpu_os", oc));
    }
    var isChromium = uaEngine === "chromium";
    // Chrome wraps its (unmasked) WebGL renderer in "ANGLE (...)" on every desktop backend — D3D11, Metal,
    // Vulkan, and even SwiftShader. A Chromium UA whose renderer is a BARE GPU string (no "ANGLE (" prefix)
    // is the common renderer spoof: the anti-detect tool replaced the ANGLE wrapper with a hardware GPU
    // name. Verified real headless Chrome reports "ANGLE (Google, Vulkan ... SwiftShader ...)" → no fire.
    if (isChromium && wg.renderer && !/^ANGLE \\(/.test(wg.renderer)) sigs.push(S("browser", "webgl_not_angle", true));
    // Stale-template / version-inflation tell — the JS-engine analog of net.tls_pq_keyshare_vs_ua: a
    // hardcoded modern Chrome UA running on an OLDER Chromium build. Promise.withResolvers shipped in
    // Chrome 119, so a UA claiming Chrome >= 121 without it is an engine older than it claims. FP-safe:
    // every real Chrome >= 119 has it (verified Chrome 136 has it).
    var uaChrome = parseInt((ua.match(/Chrome\\/(\\d+)/) || [])[1] || "0", 10);
    if (isChromium && uaChrome >= 121 && typeof Promise.withResolvers !== "function")
      sigs.push(S("browser", "engine_feature_vs_ua", true));
    // The Runtime.enable leak is CDP-specific (Chromium). Guarded to Chromium to avoid odd Firefox cases.
    if (isChromium && cdpRuntimeEnabled()) sigs.push(S("browser", "cdp_runtime_enabled", true));
    if (!navigator.languages || navigator.languages.length === 0) sigs.push(S("browser", "languages_empty", true));
    // Primary language subtag the JS layer reports — cross-checked against the HTTP Accept-Language at
    // the edge (net.accept_lang_vs_navigator). A locale spoofed in JS but not in the HTTP stack mismatches.
    var _nl = (navigator.languages && navigator.languages[0]) || navigator.language || "";
    if (_nl) sigs.push(S("browser", "nav_language_primary", String(_nl).split("-")[0].toLowerCase()));
    if (!screen.width || !screen.height || window.outerWidth === 0 || window.outerHeight === 0) sigs.push(S("browser", "screen_zero", true));
    // Raw screen geometry + colour depth as VALUES (not just the anomaly tells) — the prevalence model
    // scores how probable the platform/gpu/screen/colour/cores combination is under a real-traffic prior.
    if (screen.width && screen.height) sigs.push(S("browser", "screen_resolution", screen.width + "x" + screen.height));
    if (screen.colorDepth) sigs.push(S("browser", "color_depth", screen.colorDepth));
    // CreepJS/sannysoft: the available screen can never exceed the physical screen — avail > total is an
    // impossible value only a spoofed/sloppily-randomised screen produces (no zoom/dpr confound; both logical px).
    if (screen.availWidth > screen.width || screen.availHeight > screen.height) sigs.push(S("browser", "screen_impossible", true));
    if (isChromium && !navigator.connection) sigs.push(S("browser", "chrome_no_connection", true));
    if (isChromium && navigator.pdfViewerEnabled === false) sigs.push(S("browser", "chrome_no_pdfviewer", true));
    if (window.chrome && !window.chrome.runtime) sigs.push(S("browser", "chrome_runtime_missing", true));
    if (navigator.maxTouchPoints > 0 && !/Mobile|Android|iPhone|iPad/i.test(ua)) sigs.push(S("browser", "maxtouch_desktop", true));
    if (navigator.mimeTypes && navigator.mimeTypes.length === 0) sigs.push(S("browser", "mimetypes_empty", true));
    if (isChromium && typeof navigator.deviceMemory === "undefined") sigs.push(S("browser", "chrome_no_devicememory", true));
    try { if (window.Notification && Notification.permission === "denied") sigs.push(S("browser", "notification_denied", true)); } catch (e) {}
    // --- v0.26.0: canvas farbling (Brave) — reference-free. A farbling browser adds per-session noise to
    // canvas readback; a solid fill is the probe: a real browser reads back the EXACT colour, a farbling
    // one perturbs some pixels. (canvas_lie catches a JS getImageData override; this catches engine-level
    // farbling, where getImageData is still native.) Read the interior only to avoid any edge AA.
    try {
      var fc = document.createElement("canvas"); fc.width = 64; fc.height = 64;
      var fctx = fc.getContext("2d");
      fctx.fillStyle = "rgb(123, 77, 211)"; fctx.fillRect(0, 0, 64, 64);
      var fdata = fctx.getImageData(16, 16, 32, 32).data;
      for (var fi = 0; fi < fdata.length; fi += 4) {
        if (fdata[fi] !== 123 || fdata[fi + 1] !== 77 || fdata[fi + 2] !== 211 || fdata[fi + 3] !== 255) {
          sigs.push(S("browser", "canvas_noise", true));
          break;
        }
      }
    } catch (e) {}
    // --- v0.72.0: canvas GEOMETRY farbling (JShelter et al.) — reference-free, GPU-independent. canvas
    // isPointInPath/isPointInStroke are EXACT geometric hit-tests (nonzero/evenodd fill rule, no
    // rasterization, no AA for a point far from the boundary) — deterministic in every real engine,
    // headless or not. JShelter's canvas farbling wraps them to flip the answer with ~5% probability to
    // poison fingerprinting; over many trials on a point DEEP inside (and one far outside) a real browser
    // never errs, a farbled one does. Distinct from canvas_noise (readback farbling, e.g. Brave). Gated
    // on a definitive interior/exterior point so sub-pixel ambiguity cannot misfire; missing API never fires.
    try {
      var gc = document.createElement("canvas"); gc.width = 100; gc.height = 100;
      var gctx = gc.getContext("2d");
      if (gctx && typeof gctx.isPointInPath === "function") {
        gctx.beginPath(); gctx.rect(20, 20, 60, 60);   // square (20,20)-(80,80)
        var geomBad = false;
        for (var pi = 0; pi < 120; pi++) {
          // (50,50) is 30px inside every edge; (5,5) is 15px outside — exact in any real 2D engine.
          if (gctx.isPointInPath(50, 50) !== true || gctx.isPointInPath(5, 5) !== false) { geomBad = true; break; }
        }
        if (geomBad) sigs.push(S("browser", "canvas_geometry_noise", true));
      }
    } catch (e) {}
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
    // --- v0.47.0: detections mined from the survey (docs/landscape.md). ---
    // FingerprintJS BotD / bot.sannysoft.com: Electron/Node globals, Playwright/Puppeteer hooks, and
    // webdriver attributes on documentElement — none of which a real browser on this (own) page exposes.
    var autoGlobals = ["Buffer", "process", "global", "require", "__playwright__", "__pw_manual",
      "__puppeteer_evaluation_script__", "__puppeteer__", "_playwright", "fmget_targets"];
    var autoHit = autoGlobals.some(function (k) { return k in window; });
    try {
      var de = document.documentElement;
      autoHit = autoHit || ["webdriver", "selenium", "driver"].some(function (a) { return de.getAttribute(a) !== null; });
    } catch (e) {}
    if (autoHit) sigs.push(S("browser", "automation_globals", true));
    try { if (!document.createElement("canvas").getContext("webgl2")) sigs.push(S("browser", "webgl2_missing", true)); } catch (e) {}
    // --- v0.23.0 wave: WebGPU (the emerging GPU fingerprint vector). Explore what the engine exposes;
    // a spoof that fixes the WebGL renderer may leave the WebGPU adapter (vendor/architecture/fallback)
    // betraying the real/software GPU — a fresh coherence surface below the WebGL spoof.
    try {
      if (navigator.gpu && navigator.gpu.requestAdapter) {
        var gpuAdapter = await navigator.gpu.requestAdapter();
        var gpuNoHw = false;
        if (!gpuAdapter) {
          sigs.push(S("browser", "webgpu_no_adapter", true));
          gpuNoHw = true;
        } else {
          if (gpuAdapter.isFallbackAdapter) { sigs.push(S("browser", "webgpu_fallback", true)); gpuNoHw = true; }
          var ginfo = gpuAdapter.info || (gpuAdapter.requestAdapterInfo ? await gpuAdapter.requestAdapterInfo() : null);
          if (ginfo && ginfo.vendor) {
            sigs.push(S("browser", "webgpu_vendor", ginfo.vendor));
            // Headful counterpart of webgpu_webgl_vs: a *real* GPU drives a real WebGPU adapter, so the
            // adapter's GPU family must match the WebGL renderer's. A spoofer that fakes the WebGL
            // renderer to a different GPU family (while its real GPU shows through WebGPU) is exposed.
            function gpuFam(s) {
              s = (s || "").toLowerCase();
              return /nvidia|geforce|rtx|gtx/.test(s) ? "nvidia"
                   : /intel|hd graphics|\\biris\\b|uhd/.test(s) ? "intel"
                   : /\\bamd\\b|radeon|\\bati\\b/.test(s) ? "amd"
                   : /apple|\\bm1\\b|\\bm2\\b|\\bm3\\b/.test(s) ? "apple"
                   : /adreno|\\bmali\\b|powervr/.test(s) ? "mobile" : "";
            }
            var famGL = gpuFam(wg.renderer), famGPU = gpuFam(ginfo.vendor + " " + (ginfo.architecture || ""));
            if (famGL && famGPU && famGL !== famGPU) sigs.push(S("browser", "webgpu_vendor_mismatch", true));
          }
        }
        // Coherence: WebGL renderer claims a *hardware* GPU, but WebGPU exposes no real adapter. A genuine
        // hardware GPU drives both, so this means the WebGL renderer was spoofed — caught below the spoof.
        // (A VM/VDI with honest software WebGL does NOT trip this: its renderer is SwiftShader, not "hardware".)
        var webglHw = wg.renderer && !/swiftshader|llvmpipe|software|mesa|angle \\(google/i.test(wg.renderer);
        if (gpuNoHw && webglHw) sigs.push(S("browser", "webgpu_webgl_mismatch", true));
      } else {
        sigs.push(S("browser", "webgpu_absent", true));
      }
    } catch (e) {}
    // --- v0.11.0 wave: installed-font OS fingerprint (the engine-level OS-lie counter) ---
    var fo = fontOSHint();
    if (fo) sigs.push(S("browser", "font_os_hint", fo));
    // --- v0.17.0 wave: font construction artifacts (white-box: Camoufox's fixed per-OS font lists) ---
    // Arimo/Cousine/Tinos are Google metric-compatible fonts that ship on Linux (Camoufox's lin list
    // only). Measurable under a non-Linux UA → the real Linux container is leaking through the spoof.
    var plat = uaPlatform(ua);
    if (plat && plat !== "Linux" && (fontPresent("Arimo") || fontPresent("Cousine") || fontPresent("Tinos")))
      sigs.push(S("browser", "font_linux_leak", true));
    // macOS internal dot-prefixed fonts (.Aqua Kana, .Apple Color Emoji UI) are never web-measurable on
    // a real Mac; if measurable, an anti-detect tool naively exposed its bundled system-font list.
    if (fontPresent(".Aqua Kana") || fontPresent(".Apple Color Emoji UI"))
      sigs.push(S("browser", "font_mac_internal", true));
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
    // --- v0.21.0: timezone consistency (CreepJS "timezone lie"). The IANA timeZone and the numeric
    // getTimezoneOffset() must agree — a real browser derives both from the OS. A spoof that sets one but
    // not the other (or forces UTC over a real offset) is self-inconsistent. Near-zero false positives.
    try {
      var tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      if (tz) {
        var dnow = new Date();
        var off = dnow.toLocaleString("en-US", { timeZone: tz, timeZoneName: "longOffset" });
        var m = off.match(/GMT([+-]\\d{1,2})(?::(\\d{2}))?/);
        if (m) {
          var implied = -(parseInt(m[1], 10) * 60 + (m[1][0] === "-" ? -1 : 1) * (m[2] ? parseInt(m[2], 10) : 0));
          if (Math.abs(implied - dnow.getTimezoneOffset()) > 1)
            sigs.push(S("browser", "timezone_inconsistent", true));
        }
        // resistFingerprinting (Tor Browser / Mullvad / RFP-Firefox) evades by making every user look
        // IDENTICAL: it forces the timezone to UTC, letterboxes the content window to 200x100 multiples,
        // and clamps hardwareConcurrency to 2. Each trait alone is common (a UK user, a round window, a
        // 2-core VM); all three together is the RFP signature — so require the conjunction, not any one.
        var rfpUTC = tz === "UTC";
        var rfpBox = window.innerWidth > 0 && window.innerWidth % 200 === 0 && window.innerHeight % 100 === 0;
        var rfpCores = (navigator.hardwareConcurrency || 99) <= 2;
        if (rfpUTC && rfpBox && rfpCores) sigs.push(S("browser", "rfp_browser", true));
      }
    } catch (e) {}
    // --- v0.15.0 wave: media-capability gaps (audio fingerprint + media-device enumeration) ---
    var af = await audioFP();
    if (af.missing) sigs.push(S("browser", "audio_missing", true));
    else if (af.noise) sigs.push(S("browser", "audio_noise", true));
    // Audio readback consistency: getChannelData and copyFromChannel read the SAME buffer, so on a real
    // engine they are bit-identical (verified diff=0 on Chrome). A farbling browser that perturbs the
    // fingerprint-readable getChannelData path but not copyFromChannel (or vice-versa) diverges — a deeper
    // audio-noise tell than audio_noise (render determinism). Fires on privacy browsers (Brave/Camoufox)
    // too, so it corroborates rather than convicts. Unlike canvas putImageData round-trips (lossy by
    // premultiplied alpha on every real browser), the same-buffer audio readback is exact.
    try {
      var OAC2 = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (OAC2) {
        var rbCtx = new OAC2(1, 2048, 44100), rbBuf = rbCtx.createBuffer(1, 2048, 44100);
        var rbCh = rbBuf.getChannelData(0);
        for (var rbi = 0; rbi < 2048; rbi++) rbCh[rbi] = Math.sin(rbi / 10);
        var rbCopy = new Float32Array(2048);
        rbBuf.copyFromChannel(rbCopy, 0);
        var rbDiff = 0;
        for (var rbj = 0; rbj < 2048; rbj++) if (rbCh[rbj] !== rbCopy[rbj]) rbDiff++;
        if (rbDiff > 0) sigs.push(S("browser", "audio_readback_noise", true));
      }
    } catch (e) {}
    // --- v0.44.0: high-entropy fingerprint hash (the profile-reuse / cloned-identity tell). A canvas-text
    // render + the audio sum + the WebGL renderer/vendor combine into one stable hash that varies per
    // GPU/driver/OS/font-stack — so two *real* machines, even on the same browser build, hash differently.
    // A native anti-detect browser (e.g. BotBrowser) that reuses one fingerprint profile across a fleet
    // emits the *identical* hash from every instance; the coordination scorer keys on that collision across
    // distinct IPs (the complement of the JS-divergence paradox). Deterministic + reference-free + headless.
    try {
      var hc = document.createElement("canvas"); hc.width = 240; hc.height = 60;
      var hx = hc.getContext("2d");
      hx.textBaseline = "alphabetic"; hx.fillStyle = "#f60"; hx.fillRect(125, 1, 62, 20);
      hx.fillStyle = "#069"; hx.font = "11pt no-real-font-123";
      hx.fillText("Kitsune 🦊 fp ⒶⒷ", 2, 15);
      hx.fillStyle = "rgba(102, 204, 0, 0.7)"; hx.font = "18pt Arial";
      hx.fillText("Kitsune 🦊 fp ⒶⒷ", 4, 45);
      var hd = hx.getImageData(0, 0, 240, 60).data;
      var h = 0x811c9dc5;  // FNV-1a/32 over canvas pixels, then folded with audio + WebGL identity
      for (var hi = 0; hi < hd.length; hi += 4) {
        h ^= hd[hi]; h = (h * 0x01000193) >>> 0;
      }
      var tail = (af.missing ? "" : String(af.value)) + "|" + (wg.renderer || "") + "|" + (wg.vendor || "");
      for (var ti = 0; ti < tail.length; ti++) {
        h ^= tail.charCodeAt(ti); h = (h * 0x01000193) >>> 0;
      }
      sigs.push(S("browser", "fp_hash", ("0000000" + h.toString(16)).slice(-8)));
    } catch (e) {}
    // --- v0.19.0 wave: WebRTC ICE probe (real network identity / the bots-DDoS frontier) ---
    var rtc = await webrtcProbe();
    if (rtc.unavailable || !rtc.any) sigs.push(S("browser", "webrtc_unavailable", true));
    if (rtc.pub) sigs.push(S("browser", "webrtc_public_ip", rtc.pub));  // for cross-layer IP correlation
    // Camoufox does NOT spoof multimediaDevices (per its browserforge cast map), so enumerateDevices()
    // reflects the real container, which has no audio/video hardware — a real desktop is never empty.
    try {
      if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
        var devs = await navigator.mediaDevices.enumerateDevices();
        if (!devs || devs.length === 0) sigs.push(S("browser", "media_devices_empty", true));
      }
    } catch (e) {}
    // Camoufox does NOT spoof audio/video codec support (per its browserforge cast map). Real Firefox on
    // Windows/macOS plays proprietary H.264/AAC via OS codecs; a minimal Linux container often cannot — so
    // a non-Linux UA that cannot play H.264 is the real container OS leaking through the spoof.
    try {
      var vEl = document.createElement("video"), aEl = document.createElement("audio");
      var h264 = vEl.canPlayType('video/mp4; codecs="avc1.42E01E"');
      var aac = aEl.canPlayType('audio/mp4; codecs="mp4a.40.2"');
      var plat2 = uaPlatform(ua);
      if (plat2 && plat2 !== "Linux" && h264 === "" && aac === "")
        sigs.push(S("browser", "codec_os_incoherent", true));
    } catch (e) {}
    // Read the adblock bait: a content blocker (Camoufox ships uBlock Origin by default) hides it.
    try {
      if (_bait && _bait.parentNode) {
        var hidden = _bait.offsetHeight === 0 || _bait.offsetParent === null
          || getComputedStyle(_bait).display === "none";
        if (hidden) sigs.push(S("browser", "adblock_present", true));
      }
    } catch (e) {}
    // Camoufox pins devicePixelRatio to 1.0 (its source: "any value other than 1.0 is suspicious"), but
    // a modern Mac is Retina (dPR 2). A macOS UA reporting dPR exactly 1.0 is therefore incoherent.
    if (uaPlatform(ua) === "macOS" && window.devicePixelRatio === 1) sigs.push(S("browser", "macos_dpr1", true));
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
    // Language realm coherence: navigator.languages must agree across the main thread and a Worker; a
    // main-realm geo-spoof of navigator.languages never reaches Worker scope.
    if (wn && wn.lang && navigator.languages.length > 0 && wn.lang !== navigator.languages.join(",")) {
      sigs.push(S("browser", "languages_worker_divergence", true));
    }
    // GPU realm coherence: the WebGL renderer must agree across the main thread and a Worker OffscreenCanvas
    // (one physical GPU). A getParameter spoof patches the main realm but never the Worker → divergence.
    var wglr = await workerGlRenderer();
    if (wglr && wg.renderer && wglr !== wg.renderer) {
      sigs.push(S("browser", "webgl_worker_divergence", true));
    }
    var mch = mainCanvasHashCW();
    var wch = await workerCanvasHashCW();
    if (mch !== null && wch !== null && mch !== wch) {
      sigs.push(S("browser", "canvas_worker_divergence", true));
    }
    var mainTz = ""; try { mainTz = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch (e) {}
    var mainOff = new Date().getTimezoneOffset();
    var wtz = await workerTz();
    if (wtz && (wtz.off !== mainOff || (mainTz !== "" && wtz.tz !== "" && wtz.tz !== mainTz))) {
      sigs.push(S("browser", "timezone_worker_divergence", true));
    }
    // Internal timezone coherence: the IANA zone's current UTC offset must equal -getTimezoneOffset() (both
    // derive from one OS setting). A naive geo-spoof patches one and forgets the other; a legit CDP override
    // keeps both consistent.
    try {
      if (mainTz !== "") {
        var tzParts = new Intl.DateTimeFormat("en-US", { timeZone: mainTz, timeZoneName: "longOffset" }).formatToParts(new Date());
        var tzn = ""; for (var ti = 0; ti < tzParts.length; ti++) { if (tzParts[ti].type === "timeZoneName") tzn = tzParts[ti].value; }
        var zoneEast = null;
        if (tzn === "GMT" || tzn === "UTC") zoneEast = 0;
        else { var zm = /GMT([+-])(\\d{2}):?(\\d{2})?/.exec(tzn); if (zm) zoneEast = (zm[1] === "-" ? -1 : 1) * (parseInt(zm[2], 10) * 60 + parseInt(zm[3] || "0", 10)); }
        if (zoneEast !== null && zoneEast !== -mainOff) sigs.push(S("browser", "timezone_internal_incoherent", true));
      }
    } catch (e) {}
    // CSP was not enforced on a page that ships a strict img-src — the context bypassed CSP (only an
    // automation framework does this). Emitted in every mode: it is an automation tell, not behavioural.
    if (!cspEnforced) sigs.push(S("browser", "csp_bypassed", true));
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
      // Biomechanics: only with enough of a movement to expect human structure (matches the Balabit
      // calibration's min segment length). Real hands make corrective sub-movements, pause, and obey the
      // 2/3 power law; a Bezier humanizer does none of these (docs/behavioral-data.md).
      if (pts.length >= 12) {
        sigs.push(S("behavioral", "submovement_count", submovementCount(pts)));
        sigs.push(S("behavioral", "pause_ratio", pauseRatio(pts)));
        var ple = powerLawExp(pts);
        if (ple !== null) sigs.push(S("behavioral", "power_law_exponent", ple));
        var th = traceHash(pts);
        if (th !== null) sigs.push(S("behavioral", "trace_hash", th));
      }
      if (keys.length >= 4) sigs.push(S("behavioral", "keystroke_entropy", keyEntropy(keys)));
      // Enough of a pointer stream to expect coalescing on real hardware, yet none ever occurred.
      if (coalescedSupported && ptrMoves >= 20 && coalescedMax <= 1) {
        sigs.push(S("behavioral", "coalesced_events_absent", true));
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
