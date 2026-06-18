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
  function send() {
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
    if (canvasLie()) sigs.push(S("browser", "canvas_lie", true));
    if (/Headless/i.test(ua)) sigs.push(S("browser", "ua_is_headless", true));
    sigs.push(S("behavioral", "mouse_entropy", entropy(pts)));
    sigs.push(S("behavioral", "pointer_event_count", pts.length));
    fetch("/ingest", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sigs) })
      .then(function () { document.body.setAttribute("data-ks", "sent"); });
  }
  setTimeout(send, 2500);
})();
</script></body></html>
"""
