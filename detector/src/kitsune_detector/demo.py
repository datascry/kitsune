# detector/demo — the in-browser demo page served to real (or evader-driven) browsers.
# Inline collector mirroring the TS collector library; posts browser+behavioral signals to /ingest.

"""The demo page.

A real browser loads this (through the edge, which fingerprints the TLS handshake and sets ``ks_sid``).
The inline script reads ``ks_sid``, collects the same browser/behavioral tells the TypeScript
``collector`` library does, and POSTs them to ``/ingest`` (same origin → proxied to the detector),
joining the network signals into one session.
"""

from __future__ import annotations

from pathlib import Path

from .styles import SHARED_CSS

DEMO_PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Antidetect &amp; browser fingerprint test — Kitsune</title>
<meta name="description" content="Is your browser or antidetect setup detectable? Kitsune fingerprints your browser, TLS/JA4, HTTP-2, QUIC, TCP/IP and behavior, then flags incoherence across layers — the real bot-detection verdict, live.">
<link rel="canonical" href="https://kitsune.id/">
<meta name="robots" content="index, follow">
<meta name="theme-color" content="#0a0a0c">
<meta property="og:type" content="website">
<meta property="og:site_name" content="Kitsune">
<meta property="og:title" content="Antidetect &amp; browser fingerprint test — Kitsune">
<meta property="og:description" content="Is your stealth browser detectable? Live cross-layer fingerprint, TLS/JA4 and bot-detection test.">
<meta property="og:url" content="https://kitsune.id/">
<meta property="og:image" content="https://kitsune.id/og.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Antidetect &amp; browser fingerprint test — Kitsune">
<meta name="twitter:description" content="Is your stealth browser detectable? Live cross-layer fingerprint, TLS/JA4 and bot-detection test.">
<meta name="twitter:image" content="https://kitsune.id/og.png">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
<link rel="stylesheet" href="/home.css">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebApplication","name":"Kitsune","url":"https://kitsune.id/","applicationCategory":"SecurityApplication","operatingSystem":"Any","offers":{"@type":"Offer","price":"0","priceCurrency":"USD"},"description":"Antidetect & browser fingerprint test: cross-layer fingerprint, TLS/JA4, HTTP-2, QUIC, TCP/IP and bot detection."}</script>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"FAQPage","mainEntity":[{"@type":"Question","name":"What is a browser fingerprint?","acceptedAnswer":{"@type":"Answer","text":"The combination of signals a site reads from your browser — canvas/WebGL rendering, fonts, screen, audio, Client Hints and more — that together identify your device without cookies. Kitsune enumerates them and scores how coherent they are."}},{"@type":"Question","name":"Can antidetect browsers beat fingerprinting?","acceptedAnswer":{"@type":"Answer","text":"Stealth/antidetect browsers spoof many signals, but making every layer agree — TLS JA4, HTTP-2 frame order, TCP/IP stack, GPU renderer and the JS feature-set all consistent with one real device — is far harder. Kitsune flags the contradictions that remain."}},{"@type":"Question","name":"What is JA3 / JA4 TLS fingerprinting?","acceptedAnswer":{"@type":"Answer","text":"JA3 and JA4 fingerprint the TLS ClientHello your browser sends on connect. They identify the TLS stack, which often betrays an automation tool even when the User-Agent looks normal. Kitsune's edge reads yours from the raw connection."}},{"@type":"Question","name":"Is my browser detectable as a bot?","acceptedAnswer":{"@type":"Answer","text":"Run the test above: Kitsune scores your browser across network, browser, behavioral and reputation layers and returns a live verdict — human, suspicious, or bot — with the exact signals that fired."}},{"@type":"Question","name":"Does this send my data anywhere?","acceptedAnswer":{"@type":"Answer","text":"No. Your signals are scored by Kitsune's detector at this origin only to compute the verdict you see, and held only in memory for that — they are never written to disk, never retained after the response, never sold, shared, or used to track you across visits. The store runs in-memory and is empty again on restart. There are no third-party trackers on the page."}}]}</script>
</head>
<body>
<a class="skip-link" href="#test">Skip to the detection test</a>
<nav class="top" aria-label="Primary">
  <a class="brand" href="/" aria-current="page">Kitsune</a>
  <a href="/arena">Arena</a>
  <a href="/how-it-works">How it works</a>
  <a href="/docs">Docs</a>
  <a href="https://github.com/datascry/kitsune">GitHub</a>
  <span class="spacer"></span>
</nav>
<main>
<section id="test">
  <h1 class="page">Antidetect &amp; browser fingerprint test</h1>
  <p class="lead"><strong>Is this browser detectable as a bot?</strong> Kitsune reads every layer — TLS, HTTP/2, TCP/IP, GPU, JavaScript, behaviour — and checks whether they tell <strong>one consistent story</strong>. A stealth or antidetect browser can fake any single layer; making them all agree is the hard part. You get the <strong>real verdict a site would reach</strong>, live.</p>
  <!-- HEADLINE: who you are + the verdict, together -->
  <p id="ks-status" role="status" aria-live="polite">Scanning your browser…</p>
  <!-- VERDICT HERO: the giant verdict + score (left) beside the coherence spine (right). showVerdict() fills
       #ks-result (verdict label/score/reason/stats) and #ks-spine (per-layer rows); renderCoherence() fills the
       predicts-vs-UA strip in #ks-coherence. All IDs preserved so the render/publish/lazy paths are unchanged. -->
  <section class="vhero" aria-live="polite">
    <div class="vh-main">
      <div class="eyebrow">Verdict &middot; this browser</div>
      <div id="ks-result"><div class="vh-big"><span class="vh-label display" style="color:var(--muted)">&hellip;</span><span class="vh-score display">scoring your browser&hellip;</span></div></div>
      <div id="ks-cta"></div>
    </div>
    <div class="vh-spine">
      <div class="eyebrow">Coherence spine</div>
      <div id="ks-spine"></div>
      <div id="ks-coherence"></div>
    </div>
  </section>
  <div class="ks-actions">
    <button type="button" id="ks-rerun" class="ks-btn primary">↻ Re-run scan</button>
  </div>
  <!-- MACHINE-READABLE RESULT: automated tools can parse the verdict here without scraping the DOM.
       It starts as {"status":"collecting"} and is replaced with the full verdict (label, score,
       incoherence_score, layer_scores, contradictions[], session_id, and a wire{} block) once scoring
       completes — status becomes "complete". Also exposed as window.ksResult and a "kitsune:result"
       event. Poll this element's textContent, or: addEventListener("kitsune:result", e => e.detail). -->
  <script type="application/json" id="ks-verdict">{"status":"collecting"}</script>
  <div id="ks-fpid" class="fpid">Scanning your browser…</div>
  <!-- Below the verdict hero, the mock's compact rhythm: the live behavioral spotlight, then the fired
       detections. The deep forensic evidence (predicted browser, wire layer, surfaces, full detections)
       follows as click-to-open disclosures — present, but not a wall of data under the verdict. -->
  <section id="ks-bio" aria-label="behavioral biometrics" class="bio-spot">
    <h2>Behavioral layer &mdash; live</h2>
    <p class="bio-help">Type a sentence and move your mouse &mdash; or <b>swipe</b> on a touch screen. Your mouse/touch dynamics and keystroke timing are measured live and re-score the verdict automatically once there's enough input.</p>
    <div class="bio-grid">
      <div class="bio-controls">
        <input id="ks-bio-text" type="text" autocomplete="off" spellcheck="false" placeholder="Type a sentence here to measure keystroke timing…">
      </div>
      <div id="ks-bio-metrics" class="bio-metrics">move your mouse, swipe, and type below to measure&hellip;</div>
    </div>
  </section>
  <!-- Fired-detections spotlight — what convicts this session. -->
  <section class="panel fired-spot" id="ks-fired"></section>
  <!-- EVIDENCE panels: the same bordered-panel language as the verdict + behavioral layer, always visible, so
       the page reads as one cohesive stack rather than a row of dropdowns. Each still paints when its data
       arrives (ksLazyTouch renders eagerly for a non-collapsible panel). -->
  <section class="panel" id="ks-predict-d"><h2>Predicted browser <span class="note">&mdash; from feature detection, independent of the User-Agent</span></h2><div id="ks-predict"></div></section>
  <section class="panel" id="ks-wire-d"><h2>Network / wire layer <span class="note">&mdash; TLS/JA4, HTTP-2, QUIC, TCP/IP, read from your raw connection by Kitsune&rsquo;s edge</span></h2><div id="ks-wire"></div></section>
  <section class="panel" id="ks-surfaces-d"><h2>Fingerprint surfaces <span class="note">&mdash; every enumerated value &middot; tamper status<span id="ks-surf-count"></span></span></h2><div id="ks-surfaces"></div></section>
</section>
<section id="how-it-works">
  <h2>How Kitsune detects bots &amp; antidetect browsers</h2>
  <div class="prose">
    <p>Most fingerprint testers list signals. Kitsune flags <strong>incoherence across layers</strong> — the contradictions a real browser cannot produce but a spoofed or automated one does. The User-Agent, the TLS handshake, the HTTP-2 frames, the TCP/IP stack, the GPU and the JavaScript feature-set all have to describe <em>one</em> coherent device. When they disagree, that is the tell.</p>
    <p>It scores seven layers: <strong><abbr title="A fingerprint of the TLS handshake your browser sends on connect — it identifies the network stack underneath the browser, which often betrays an automation tool even when the User-Agent looks normal.">TLS/JA4</abbr></strong>, <strong><abbr title="The HTTP/2 frame-order and SETTINGS fingerprint — each browser's HTTP/2 stack has a recognisable shape.">HTTP-2</abbr></strong>, <strong><abbr title="QUIC / HTTP-3 — the UDP-based transport modern Chrome uses; its handshake fingerprints the stack too.">QUIC/HTTP-3</abbr></strong> and <strong><abbr title="The TCP/IP packet fingerprint (p0f-style) — reveals the operating-system network stack.">TCP/IP-OS</abbr></strong> read from the raw connection by Kitsune's edge; <strong>canvas, WebGL, audio, fonts and Client Hints</strong> in the browser; <strong>mouse and keystroke dynamics</strong>; and <strong>IP reputation</strong>. Every rule is data in a public registry — the same rules the server runs.</p>
    <p>An antidetect browser can spoof the User-Agent and patch <code>navigator.webdriver</code>, but making the JA4, the frame order, the TCP stack, the GPU renderer and the JS surface all agree on one real device is much harder — and that is exactly what this page measures.</p>
  </div>
</section>
<section id="faq" class="faq">
  <h2>FAQ</h2>
  <details><summary>What is a browser fingerprint?</summary><p>The combination of signals a site reads from your browser — canvas/WebGL rendering, fonts, screen, audio, Client Hints and more — that together identify your device without cookies. Kitsune enumerates them and scores how coherent they are.</p></details>
  <details><summary>Can antidetect browsers beat fingerprinting?</summary><p>Stealth/antidetect browsers (Camoufox, undetected-chromedriver, multilogin, …) spoof many signals, but making every layer agree — TLS JA4, HTTP-2 frame order, TCP/IP stack, GPU renderer and the JS feature-set all consistent with one real device — is far harder. Kitsune flags the contradictions that remain.</p></details>
  <details><summary>What is JA3 / JA4 TLS fingerprinting?</summary><p>JA3 and JA4 fingerprint the TLS ClientHello your browser sends on connect. They identify the TLS stack, which often betrays an automation tool even when the User-Agent looks normal. Kitsune's edge reads yours from the raw connection.</p></details>
  <details><summary>Is my browser detectable as a bot?</summary><p>Run the test above: Kitsune scores your browser across network, browser, behavioral and reputation layers and returns a live verdict — human, suspicious, or bot — with the exact signals that fired.</p></details>
  <details><summary>Does this send my data anywhere?</summary><p>No. Your signals are scored by Kitsune's detector at this origin to compute the verdict you see, and held only in memory for that — they are <strong>never written to disk, never retained after the response, never sold, shared, or used to track you across visits</strong>. The store runs in-memory and is empty again on restart. There are no third-party trackers on this page. See the <a href="https://github.com/datascry/kitsune/blob/main/docs/privacy.md">privacy notice</a>.</p></details>
</main>
<footer><p><strong>No data captured.</strong> Kitsune computes your verdict from this visit alone and shows it to you — your signals stay in memory, are never written to disk, sold, shared, or used to track you, and there are no third-party trackers. It is the blue-team side of an open-source bot detection ⇄ evasion lab. <a href="https://github.com/datascry/kitsune">Source</a> · <a href="https://github.com/datascry/kitsune/blob/main/docs/privacy.md">Privacy</a>.</p>
<p class="note">IP Geolocation by <a href="https://db-ip.com">DB-IP</a> (CC BY 4.0).</p></footer>
<script src="/home.js"></script></body></html>
"""

# Inject the shared design tokens + a11y foundation (one source with the doc pages — see styles.SHARED_CSS).
# The home page CSS now lives in static/home.css (a real, lintable file); serve it (with the shared
# design tokens prepended) at /home.css, linked from DEMO_PAGE — the client CSS is out of the HTML string.
HOME_CSS = (
    SHARED_CSS.rstrip()
    + "\n"
    + (Path(__file__).parent / "static" / "home.css").read_text(encoding="utf-8").rstrip()
    + "\n"
)
