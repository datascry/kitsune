// harness/tools/captcha_probe — client-side instrumentation to learn a captcha widget's FUNCTION (clean-room).
// Installs BEFORE page scripts, wraps the fingerprint/behavioural/network JS APIs, and records every access in
// order so the widget's behaviour reduces to a structured functional spec — without reading a byte of its code.

(() => {
  "use strict";
  if (window.__KS_PROBE__) return; // install once

  // --- the ledger: aggregate accesses by API, keep the FIRST-touch time + order + a few sample args ---
  const T0 = performance && performance.now ? performance.now() : Date.now();
  const now = () => Math.round((performance && performance.now ? performance.now() : Date.now()) - T0);
  const access = new Map(); // "cat:name" -> {cat,name,count,firstMs,samples[]}
  const listeners = new Map(); // event type -> {count,firstMs}
  const network = []; // ordered {ms,method,url,kind,body}

  function record(cat, name, sample) {
    const key = cat + ":" + name;
    let e = access.get(key);
    if (!e) {
      e = { cat, name, count: 0, firstMs: now(), samples: [] };
      access.set(key, e);
    }
    e.count++;
    if (sample != null && e.samples.length < 4) {
      const s = String(sample).slice(0, 48);
      if (e.samples.indexOf(s) < 0) e.samples.push(s);
    }
  }
  function recordListener(type) {
    let e = listeners.get(type);
    if (!e) e = listeners.set(type, { count: 0, firstMs: now() }).get(type);
    e.count++;
  }
  function bodyShape(body) {
    try {
      if (body == null) return null;
      if (typeof body === "string") {
        try {
          return Object.keys(JSON.parse(body)).slice(0, 24);
        } catch (_) {
          return "<" + body.length + "b>";
        }
      }
      if (typeof FormData !== "undefined" && body instanceof FormData) {
        const k = [];
        body.forEach((_v, key) => k.push(key));
        return k.slice(0, 24);
      }
      if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) return Array.from(body.keys()).slice(0, 24);
      return typeof body;
    } catch (_) {
      return null;
    }
  }
  function recordNet(method, url, kind, body) {
    network.push({ ms: now(), method: method || "GET", url: String(url).slice(0, 220), kind, body: bodyShape(body) });
  }

  // --- stealth: a captcha checks Function.prototype.toString to detect wrapped APIs. Track our wrappers and make
  //     toString report native code for them, so the probe doesn't perturb what it measures (the same trick evaders
  //     use — and a good lesson: instrumentation must be coherent or it changes the behaviour it observes). ---
  const wrapped = new WeakSet();
  const mark = (fn) => (wrapped.add(fn), fn);
  const origToString = Function.prototype.toString;
  Function.prototype.toString = mark(function toString() {
    if (wrapped.has(this)) return "function " + (this.name || "") + "() { [native code] }";
    return origToString.call(this);
  });

  // --- interception primitives ---
  function hookGetter(proto, prop, cat, label) {
    try {
      const d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || typeof d.get !== "function") return;
      const orig = d.get;
      const get = mark(function () {
        record(cat, label || prop);
        return orig.call(this);
      });
      Object.defineProperty(proto, prop, { configurable: true, enumerable: d.enumerable, get, set: d.set });
    } catch (_) {}
  }
  function hookMethod(obj, name, cat, label, sampleFn) {
    try {
      const orig = obj[name];
      if (typeof orig !== "function") return;
      obj[name] = mark(function () {
        record(cat, label || name, sampleFn ? sampleFn(arguments) : undefined);
        return orig.apply(this, arguments);
      });
    } catch (_) {}
  }
  function hookCtor(name, cat) {
    try {
      const O = window[name];
      if (typeof O !== "function") return;
      window[name] = new Proxy(O, {
        // a Proxy preserves prototype + instanceof, unlike a hand-rolled constructor wrapper
        construct(target, args) {
          record(cat, name);
          return Reflect.construct(target, args);
        },
      });
    } catch (_) {}
  }

  // --- FINGERPRINT surface: navigator / screen / hardware ---
  const nav = Navigator.prototype;
  ["userAgent", "platform", "hardwareConcurrency", "deviceMemory", "language", "languages", "vendor", "webdriver",
    "maxTouchPoints", "doNotTrack", "cookieEnabled", "pdfViewerEnabled", "userAgentData", "plugins", "mimeTypes",
    "connection"].forEach((p) => hookGetter(nav, p, "navigator", p));
  ["width", "height", "availWidth", "availHeight", "colorDepth", "pixelDepth"].forEach((p) => hookGetter(Screen.prototype, p, "screen", p));
  hookGetter(window, "devicePixelRatio", "screen", "devicePixelRatio");

  // --- CANVAS fingerprint (toDataURL / text metrics) ---
  hookMethod(HTMLCanvasElement.prototype, "toDataURL", "canvas", "toDataURL");
  hookMethod(HTMLCanvasElement.prototype, "toBlob", "canvas", "toBlob");
  hookMethod(HTMLCanvasElement.prototype, "getContext", "canvas", "getContext", (a) => a[0]);
  if (window.CanvasRenderingContext2D) {
    const c2 = CanvasRenderingContext2D.prototype;
    hookMethod(c2, "fillText", "canvas", "fillText", (a) => a[0]);
    hookMethod(c2, "measureText", "canvas", "measureText", (a) => a[0]); // font-enumeration probe
    hookMethod(c2, "getImageData", "canvas", "getImageData");
  }

  // --- WEBGL fingerprint (renderer/vendor via getParameter, extensions) ---
  [window.WebGLRenderingContext, window.WebGL2RenderingContext].forEach((C) => {
    if (!C) return;
    hookMethod(C.prototype, "getParameter", "webgl", "getParameter", (a) => a[0]);
    hookMethod(C.prototype, "getExtension", "webgl", "getExtension", (a) => a[0]);
    hookMethod(C.prototype, "getSupportedExtensions", "webgl", "getSupportedExtensions");
    hookMethod(C.prototype, "getShaderPrecisionFormat", "webgl", "getShaderPrecisionFormat");
    hookMethod(C.prototype, "readPixels", "webgl", "readPixels");
  });

  // --- AUDIO fingerprint (oscillator/compressor graph) ---
  [window.AudioContext, window.webkitAudioContext, window.OfflineAudioContext].forEach((C) => {
    if (!C) return;
    ["createOscillator", "createAnalyser", "createDynamicsCompressor", "createScriptProcessor", "createGain"].forEach((m) =>
      hookMethod(C.prototype, m, "audio", m),
    );
  });
  if (window.AudioBuffer) hookMethod(AudioBuffer.prototype, "getChannelData", "audio", "getChannelData");

  // --- LOCALE / capability probes ---
  if (window.Intl && Intl.DateTimeFormat) hookMethod(Intl.DateTimeFormat.prototype, "resolvedOptions", "intl", "resolvedOptions");
  hookMethod(Date.prototype, "getTimezoneOffset", "intl", "getTimezoneOffset");
  if (document.fonts && document.fonts.check) hookMethod(document.fonts, "check", "fonts", "check", (a) => a[1]);
  if (navigator.permissions) hookMethod(navigator.permissions, "query", "permissions", "query", (a) => a[0] && a[0].name);
  if (navigator.mediaDevices) hookMethod(navigator.mediaDevices, "enumerateDevices", "media", "enumerateDevices");
  hookMethod(nav, "getBattery", "battery", "getBattery");
  if (navigator.storage) hookMethod(navigator.storage, "estimate", "storage", "estimate");
  if (window.speechSynthesis) hookMethod(speechSynthesis, "getVoices", "speech", "getVoices");
  hookCtor("RTCPeerConnection", "webrtc");
  hookCtor("webkitRTCPeerConnection", "webrtc");

  // --- BEHAVIOURAL: which input events the widget subscribes to (mouse/pointer/key/touch/motion) ---
  const oAdd = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = mark(function (type) {
    recordListener(type);
    return oAdd.apply(this, arguments);
  });

  // --- NETWORK: the token/telemetry protocol (endpoints + payload SHAPE, never values) ---
  if (window.fetch) {
    const of = window.fetch;
    window.fetch = mark(function (input, init) {
      recordNet((init && init.method) || (input && input.method) || "GET", (input && input.url) || input, "fetch", init && init.body);
      return of.apply(this, arguments);
    });
  }
  const xopen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = mark(function (method, url) {
    this.__ksm = method;
    this.__ksu = url;
    return xopen.apply(this, arguments);
  });
  const xsend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = mark(function (body) {
    recordNet(this.__ksm, this.__ksu, "xhr", body);
    return xsend.apply(this, arguments);
  });
  if (Navigator.prototype.sendBeacon) {
    const ob = Navigator.prototype.sendBeacon;
    Navigator.prototype.sendBeacon = mark(function (url, data) {
      recordNet("POST", url, "beacon", data);
      return ob.apply(this, arguments);
    });
  }
  hookCtor("WebSocket", "network");

  // --- WORKER instrumentation: the probe installs per-FRAME (addInitScript) but NOT inside Web Workers, where a
  // widget can hide fingerprinting/PoW. Record every Worker/SharedWorker/ServiceWorker creation (observability, even
  // for cross-origin workers we can't enter), and for SAME-ORIGIN classic workers reweave a worker-safe probe ahead
  // of the real script (importScripts) so its reads report back via postMessage. Cross-origin is record-only and
  // SAFE — never breaks the real worker. ---
  const WORKER_PROBE_SRC = `(function(){try{
    var acc={}, rec=function(c,n){var k=c+':'+n; acc[k]=(acc[k]||0)+1;};
    var WN=self.WorkerNavigator&&self.WorkerNavigator.prototype;
    if(WN)['userAgent','hardwareConcurrency','deviceMemory','language','platform'].forEach(function(p){try{
      var d=Object.getOwnPropertyDescriptor(WN,p); if(d&&d.get){var o=d.get;
      Object.defineProperty(WN,p,{configurable:true,get:function(){rec('navigator',p);return o.call(this);}});}}catch(e){}});
    var wrap=function(o,n,c){try{var f=o&&o[n]; if(typeof f==='function')o[n]=function(){rec(c,n);return f.apply(this,arguments);};}catch(e){}};
    if(self.fetch){var of=self.fetch; self.fetch=function(){rec('network','fetch');return of.apply(this,arguments);};}
    if(self.XMLHttpRequest)wrap(self.XMLHttpRequest.prototype,'open','network');
    wrap(self,'importScripts','worker');
    if(self.WebGLRenderingContext)wrap(self.WebGLRenderingContext.prototype,'getParameter','webgl');
    wrap(Date.prototype,'getTimezoneOffset','intl');
    self.addEventListener('message',function(e){if(e&&e.data&&e.data.__ksProbeReport){try{self.postMessage({__ksWorker:acc});}catch(x){}}});
  }catch(e){}})();`;
  function mergeWorkerReport(acc) {
    for (const k in acc) {
      const i = k.indexOf(":");
      for (let n = 0; n < Math.min(acc[k], 3); n++) record(k.slice(0, i), k.slice(i + 1), "worker");
    }
  }
  const _Worker = self.Worker;
  if (_Worker) {
    self.Worker = new Proxy(_Worker, {
      construct(target, args) {
        let abs = null;
        try {
          abs = new URL(String(args[0] || ""), location.href);
        } catch (_) {}
        record("worker", "Worker", (abs ? abs.href : String(args[0])).slice(0, 80));
        if (abs && abs.origin === location.origin) {
          try {
            const body = WORKER_PROBE_SRC + "\nimportScripts(" + JSON.stringify(abs.href) + ");";
            const w = Reflect.construct(target, [URL.createObjectURL(new Blob([body], { type: "text/javascript" })), args[1]]);
            w.addEventListener("message", (e) => {
              if (e && e.data && e.data.__ksWorker) mergeWorkerReport(e.data.__ksWorker);
            });
            setTimeout(() => {
              try {
                w.postMessage({ __ksProbeReport: 1 });
              } catch (_) {}
            }, 2500);
            return w;
          } catch (_) {}
        }
        return Reflect.construct(target, args); // cross-origin (or reweave failed): record-only, uninstrumented
      },
    });
  }
  if (self.SharedWorker) {
    const S = self.SharedWorker;
    self.SharedWorker = new Proxy(S, {
      construct(t, a) {
        record("worker", "SharedWorker", String(a[0] || "").slice(0, 80));
        return Reflect.construct(t, a);
      },
    });
  }
  try {
    if (navigator.serviceWorker && navigator.serviceWorker.register) {
      const reg = navigator.serviceWorker.register.bind(navigator.serviceWorker);
      navigator.serviceWorker.register = mark(function (u) {
        record("worker", "serviceWorker.register", String(u).slice(0, 80));
        return reg.apply(this, arguments);
      });
    }
  } catch (_) {}

  // --- the functional spec: ordered signal accesses + behavioural listeners + the network protocol ---
  window.__KS_PROBE__ = {
    report() {
      const signals = Array.from(access.values())
        .sort((a, b) => a.firstMs - b.firstMs)
        .map((e) => ({ ms: e.firstMs, cat: e.cat, name: e.name, count: e.count, samples: e.samples }));
      const behavioral = Array.from(listeners.entries())
        .map(([event, e]) => ({ event, count: e.count, ms: e.firstMs }))
        .sort((a, b) => a.ms - b.ms);
      return {
        url: location.href,
        counts: { signals: signals.length, listeners: behavioral.length, requests: network.length },
        signals,
        behavioral,
        network: network.slice(),
      };
    },
  };
})();
