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
<style>
:root {
  --bg: #0a0a0c;
  --panel: #0e0e12;
  --panel-2: #121218;
  --line: #20202a;
  --line-bright: #34343f;
  --ink: #eae7df; /* bone */
  --muted: #797985;
  --fox: #e8482b; /* fox-fire vermilion — the one accent */
  --jade: #5fb89a; /* clear / coherent */
  --amber: #d6a44e; /* suspicious / experimental */
  --mono:
    ui-monospace, "SF Mono", "JetBrains Mono", "Menlo", "Consolas", "Liberation Mono", monospace;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: var(--mono);
  font-size: 13.5px;
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
  letter-spacing: 0.01em;
}

header,
main,
footer {
  max-width: 64rem;
  margin: 0 auto;
  padding: 0 1.5rem;
}

/* Masthead — a vermilion rule, the wordmark, a forensic subtitle. */
header {
  padding-top: 2.5rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--line);
}
header .mark {
  display: flex;
  align-items: baseline;
  gap: 0.75rem;
}
header .mark::before {
  content: "";
  width: 0.55rem;
  height: 1.4rem;
  background: var(--fox);
  transform: translateY(0.2rem);
}
header h1 {
  margin: 0;
  font-size: 1.5rem;
  font-weight: 700;
  letter-spacing: 0.28em;
  text-transform: uppercase;
}
header .tag {
  color: var(--muted);
  font-size: 0.72rem;
  letter-spacing: 0.22em;
  text-transform: uppercase;
}
header p {
  color: var(--muted);
  max-width: 46rem;
  font-size: 0.82rem;
  margin: 0.75rem 0 0;
}
header a,
footer a {
  color: var(--fox);
  text-decoration: none;
  border-bottom: 1px solid transparent;
}
header a:hover,
footer a:hover {
  border-bottom-color: var(--fox);
}

main {
  padding-top: 1.25rem;
  padding-bottom: 2rem;
}

#status {
  color: var(--amber);
  font-size: 0.82rem;
  border-left: 2px solid var(--amber);
  padding-left: 0.75rem;
}

/* Section labels — "§ TITLE ────" with a hairline filling the row. */
h2 {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--ink);
  margin: 2rem 0 0.85rem;
}
h2::before {
  content: "§";
  color: var(--fox);
}
h2::after {
  content: "";
  flex: 1;
  height: 1px;
  background: var(--line);
}
h2 .note {
  text-transform: none;
  letter-spacing: 0;
  font-weight: 400;
}
h3 {
  font-size: 0.74rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--muted);
  margin: 1.25rem 0 0.4rem;
}
h3 .count {
  color: var(--muted);
  font-weight: 400;
}

.note {
  color: var(--muted);
  font-size: 0.78rem;
}

/* Verdict — a bordered forensic stamp, colour = result. */
/* Hero capability banner — leads the page with the full detection breadth (the MVP value prop). */
.hero {
  border: 1.5px solid var(--line-bright);
  background: var(--panel-2);
  padding: 1.25rem 1.5rem;
  margin: 1.5rem 0;
  display: flex;
  align-items: flex-end;
  gap: 2rem;
  flex-wrap: wrap;
}
.hero-stat {
  display: flex;
  flex-direction: column;
  line-height: 1.1;
}
.hero-stat strong {
  font-size: 2.4rem;
  font-weight: 700;
  color: var(--fox);
}
.hero-stat span {
  font-size: 0.72rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--muted);
}
.hero-note {
  flex: 1 1 14rem;
  margin: 0;
  color: var(--muted);
  font-size: 0.76rem;
  align-self: center;
}

.verdict {
  border: 1.5px solid var(--line-bright);
  padding: 1.25rem 1.5rem;
  margin: 1.5rem 0;
  display: flex;
  align-items: baseline;
  gap: 1.25rem;
  flex-wrap: wrap;
}
.verdict .label {
  font-size: 2rem;
  font-weight: 700;
  letter-spacing: 0.2em;
  text-transform: uppercase;
}
.verdict-bot {
  border-color: var(--fox);
}
.verdict-bot .label {
  color: var(--fox);
}
.verdict-suspicious {
  border-color: var(--amber);
}
.verdict-suspicious .label {
  color: var(--amber);
}
.verdict-human {
  border-color: var(--jade);
}
.verdict-human .label {
  color: var(--jade);
}
.verdict .score {
  font-size: 0.95rem;
}
.verdict .sub {
  color: var(--muted);
  font-size: 0.76rem;
  margin-left: auto;
}

/* Coherence banner — feature-prediction vs the claimed UA (the thesis, up front). */
.coherence {
  display: grid;
  grid-template-columns: 1fr auto 1fr;
  gap: 0.75rem;
  align-items: stretch;
  margin: 1rem 0 1.5rem;
  border: 1px solid var(--line);
}
.coherence .side {
  padding: 0.85rem 1.1rem;
}
.coherence .side .cap {
  display: block;
  font-size: 0.68rem;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--muted);
}
.coherence .side .val {
  font-size: 1rem;
  font-weight: 700;
}
.coherence .verdict-cell {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 1.25rem;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  font-size: 0.8rem;
  border-left: 1px solid var(--line);
  border-right: 1px solid var(--line);
}
.coherence.match .verdict-cell {
  color: var(--jade);
}
.coherence.mismatch {
  border-color: var(--fox);
}
.coherence.mismatch .verdict-cell {
  color: var(--fox);
}

/* Predicted-browser detail grid. */
.predict-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(7.5rem, 1fr));
  gap: 1px;
  background: var(--line);
  border: 1px solid var(--line);
}
.kv {
  background: var(--panel);
  padding: 0.6rem 0.8rem;
}
.kv .k {
  display: block;
  color: var(--muted);
  font-size: 0.66rem;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}
.kv .v {
  font-size: 1.05rem;
  font-weight: 700;
}
details.ev {
  margin-top: 0.6rem;
}
details.ev summary {
  color: var(--muted);
  font-size: 0.78rem;
  cursor: pointer;
}
details.ev ul {
  color: var(--muted);
  font-size: 0.78rem;
  margin: 0.4rem 0;
}

/* Fingerprint surfaces — value + hash + tamper status, per surface. */
.surfaces {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(15rem, 1fr));
  gap: 1px;
  background: var(--line);
  border: 1px solid var(--line);
}
.surface {
  background: var(--panel);
  padding: 0.75rem 0.9rem;
  border-top: 2px solid var(--jade);
}
.surface.tampered {
  border-top-color: var(--fox);
}
.surface .top {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
}
.surface .sname {
  font-size: 0.7rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--muted);
}
.surface .chip {
  font-size: 0.62rem;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--jade);
}
.surface.tampered .chip {
  color: var(--fox);
}
.surface .sval {
  font-size: 0.82rem;
  word-break: break-all;
  margin-top: 0.3rem;
}
.surface .shash {
  color: var(--muted);
  font-size: 0.72rem;
  margin-top: 0.2rem;
}
.surface .stells {
  color: var(--fox);
  font-size: 0.72rem;
  margin-top: 0.3rem;
}
.surface .srow {
  margin-top: 0.4rem;
}
.surface .srow .sk {
  display: block;
  color: var(--muted);
  font-size: 0.6rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.surface .srow .sv {
  font-size: 0.82rem;
  word-break: break-all;
}

/* Per-layer score bars — hairline, no gradient. */
.bar {
  display: grid;
  grid-template-columns: 7rem 1fr 3rem;
  align-items: center;
  gap: 0.6rem;
  margin: 0.3rem 0;
}
.bar-label {
  color: var(--muted);
  text-transform: uppercase;
  font-size: 0.72rem;
  letter-spacing: 0.1em;
}
.bar-track {
  background: var(--panel-2);
  height: 0.55rem;
  overflow: hidden;
  border: 1px solid var(--line);
}
.bar-fill {
  display: block;
  height: 100%;
  background: var(--fox);
}
.bar-val {
  text-align: right;
  color: var(--muted);
  font-variant-numeric: tabular-nums;
}

/* Detection tables. */
table.detections {
  width: 100%;
  border-collapse: collapse;
  margin-bottom: 1rem;
  font-size: 0.82rem;
}
table.detections th,
table.detections td {
  text-align: left;
  padding: 0.4rem 0.5rem;
  border-bottom: 1px solid var(--line);
  vertical-align: top;
}
table.detections th {
  color: var(--muted);
  font-weight: 600;
  font-size: 0.7rem;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}
td.mark {
  white-space: nowrap;
  font-variant-numeric: tabular-nums;
}
tr.fired td.mark {
  color: var(--fox);
  font-weight: 700;
}
tr.clear td.mark {
  color: var(--muted);
}
tr.clear {
  opacity: 0.5;
}
code {
  font-family: var(--mono);
  color: var(--fox);
}
.title {
  color: var(--ink);
  font-size: 0.8rem;
}
.exp {
  font-size: 0.62rem;
  color: var(--bg);
  background: var(--amber);
  padding: 0 0.3rem;
  letter-spacing: 0.05em;
}
td.weight {
  font-variant-numeric: tabular-nums;
  color: var(--muted);
}

.na {
  border-left: 2px solid var(--jade);
  padding-left: 0.85rem;
  margin: 1rem 0;
}
.na-list,
.edge-list {
  font-size: 0.78rem;
  color: var(--muted);
  margin: 0.4rem 0;
}
.na-list code {
  color: var(--jade);
}
.edge-list {
  columns: 2;
  column-gap: 2rem;
}
.layers {
  color: var(--line-bright);
}

footer {
  color: var(--muted);
  font-size: 0.78rem;
  border-top: 1px solid var(--line);
  margin-top: 2.5rem;
  padding-top: 1rem;
  padding-bottom: 2.5rem;
}

/* Behavioral live panel — the interactive biomechanics layer. */
.behavioral-panel {
  border: 1.5px solid var(--line-bright);
  background: var(--panel-2);
  padding: 1rem 1.1rem;
  margin: 1.5rem 0;
}
.bp-help {
  margin: 0.2rem 0 0.6rem;
}
.bp-pad {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  justify-content: space-between;
  margin: 0.4rem 0;
}
.bp-dot {
  flex: 1 1 auto;
  min-width: 56px;
  padding: 0.55rem;
  border: 1px solid var(--line-bright);
  background: var(--panel);
  color: inherit;
  border-radius: 4px;
  cursor: pointer;
  font: inherit;
}
.bp-dot:hover {
  background: var(--panel-2);
}
.bp-dot.hit {
  border-color: var(--ok, #2ea043);
  color: var(--ok, #2ea043);
}
.bp-text {
  width: 100%;
  box-sizing: border-box;
  padding: 0.5rem;
  margin: 0.3rem 0 0.6rem;
  border: 1px solid var(--line-bright);
  background: var(--panel);
  color: inherit;
  border-radius: 4px;
  font: inherit;
}
.bp-status {
  font-size: 0.78rem;
  color: var(--muted);
  margin: 0.3rem 0 0.6rem;
}
.bp-status .ok {
  color: var(--jade);
}
.bp-status .wait {
  color: var(--amber);
}
table.bp-table {
  width: 100%;
  border-collapse: collapse;
  margin: 0.6rem 0;
  font-size: 0.82rem;
}
table.bp-table th,
table.bp-table td {
  text-align: left;
  padding: 0.4rem 0.5rem;
  border-bottom: 1px solid var(--line);
  vertical-align: top;
}
table.bp-table th {
  color: var(--muted);
  font-weight: 600;
  font-size: 0.7rem;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}
.bp-title {
  color: var(--ink);
  font-size: 0.8rem;
}
.bp-val,
.bp-floor {
  font-variant-numeric: tabular-nums;
}
.bp-floor {
  color: var(--muted);
}
.bp-verdict {
  white-space: nowrap;
  font-weight: 700;
}
tr.bot .bp-verdict {
  color: var(--fox);
}
tr.human .bp-verdict {
  color: var(--jade);
}
tr.pending .bp-verdict {
  color: var(--amber);
  font-weight: 400;
}
tr.pending {
  opacity: 0.6;
}
.bp-summary {
  font-size: 0.8rem;
  color: var(--ink);
  margin: 0.5rem 0;
}
.bp-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin: 0.5rem 0 0;
}
button.bp-demo,
button.bp-reeval {
  font-family: var(--mono);
  font-size: 0.76rem;
  color: var(--ink);
  background: var(--panel);
  border: 1px solid var(--line-bright);
  padding: 0.4rem 0.7rem;
  cursor: pointer;
}
button.bp-demo:hover,
button.bp-reeval:hover {
  border-color: var(--fox);
  color: var(--fox);
}
.bp-dot {
  touch-action: manipulation;
}
/* L5 demo controls + banner, L6 rule provenance link, L7 share button. */
.demo-controls {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
  margin: 0.6rem 0;
}
.dc-label {
  font-size: 0.8rem;
  color: var(--muted);
}
button.demo-spoof,
button.demo-reset,
button.share-btn {
  font-family: var(--mono);
  font-size: 0.74rem;
  color: var(--ink);
  background: var(--panel);
  border: 1px solid var(--line-bright);
  padding: 0.35rem 0.6rem;
  cursor: pointer;
  border-radius: 3px;
}
button.demo-spoof:hover,
button.demo-reset:hover,
button.share-btn:hover {
  border-color: var(--fox);
  color: var(--fox);
}
.demo-banner {
  background: var(--panel-2);
  border: 1px solid var(--fox);
  padding: 0.5rem 0.8rem;
  margin: 0.5rem 0;
  font-size: 0.84rem;
}
.share-btn {
  margin-top: 0.5rem;
}
a.rule-src {
  text-decoration: none;
}
a.rule-src:hover code {
  text-decoration: underline;
}

/* --- demo-page specifics: status line, result container, server-scored behavioral panel --- */
#ks-status{color:var(--amber);font-size:.82rem;border-left:2px solid var(--amber);padding-left:.75rem;margin:1rem 0}
#ks-result{margin-top:.5rem}
.layer-bars{margin:1rem 0 1.25rem}
.bar-clean .bar-val{color:var(--jade)}.bar-clean .bar-label{color:var(--muted)}
#ks-bio{border:1.5px solid var(--line-bright);background:var(--panel-2);padding:1rem 1.1rem;margin:1.5rem 0}
.bio-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(11rem,1fr));gap:1px;background:var(--line);border:1px solid var(--line);margin:.6rem 0}
.bio-row{display:flex;align-items:baseline;justify-content:space-between;gap:.5rem;background:var(--panel);padding:.5rem .7rem;font-size:.8rem}
.bio-row span{color:var(--muted)}.bio-row b{font-variant-numeric:tabular-nums;font-weight:700}
.bio-row i{font-style:normal;font-size:.66rem;text-transform:uppercase;letter-spacing:.08em}
.bm-human{color:var(--jade)}.bm-bot{color:var(--fox);font-weight:700}.bm-collecting,.bm-more,.bm-ok,.bm-measured,.bm-na{color:var(--muted)}
.bio-head{grid-column:1/-1;background:var(--bg);color:var(--fox);font-size:.62rem;font-weight:700;text-transform:uppercase;letter-spacing:.14em;padding:.55rem .7rem .3rem}
.bio-help{color:var(--muted);font-size:.78rem;margin:.3rem 0 .6rem}
.bio-pad{display:flex;flex-wrap:wrap;gap:.5rem;justify-content:space-between;margin:.4rem 0}
.bio-dot{flex:1 1 auto;min-width:56px;padding:.55rem;border:1px solid var(--line-bright);background:var(--panel);color:inherit;border-radius:4px;cursor:pointer;font:inherit;touch-action:manipulation}
.bio-dot:hover{background:var(--panel-2)}.bio-dot.hit{border-color:var(--jade);color:var(--jade)}
#ks-bio-text{width:100%;box-sizing:border-box;padding:.5rem;margin:.3rem 0 .6rem;border:1px solid var(--line-bright);background:var(--panel);color:inherit;border-radius:4px;font:inherit}
#ks-analyze{font-family:var(--mono);font-size:.78rem;color:var(--bg);background:var(--fox);border:1px solid var(--fox);padding:.45rem .8rem;cursor:pointer;font-weight:700;letter-spacing:.04em}
#ks-analyze:hover{filter:brightness(1.12)}
/* --- landing nav --- */
nav.top{display:flex;align-items:center;gap:1.25rem;flex-wrap:wrap;max-width:64rem;margin:0 auto;padding:.9rem 1.5rem;border-bottom:1px solid var(--line)}
nav.top a{color:var(--muted);text-decoration:none;font-size:.78rem;letter-spacing:.06em}
nav.top a:hover{color:var(--fox)}
nav.top a.brand{display:flex;align-items:center;gap:.5rem;color:var(--ink);font-weight:700;letter-spacing:.22em;text-transform:uppercase;font-size:.95rem}
nav.top a.brand::before{content:"";width:.5rem;height:1.1rem;background:var(--fox)}
nav.top .spacer{flex:1}
/* --- landing prose + faq --- */
h1.page{font-size:1.85rem;font-weight:700;letter-spacing:.005em;margin:.4rem 0 0;color:var(--ink)}
.lead{font-size:1.05rem;color:var(--ink);max-width:46rem;margin:.6rem 0 .25rem}
.prose{color:var(--muted);font-size:.88rem;max-width:48rem}
.prose p{margin:.7rem 0}.prose strong{color:var(--ink)}
.faq details{border-bottom:1px solid var(--line);padding:.65rem 0}
.faq summary{cursor:pointer;color:var(--ink);font-size:.88rem;font-weight:600}
.faq details p{color:var(--muted);font-size:.84rem;margin:.5rem 0 0;max-width:48rem}
/* --- composite fingerprint ID + per-layer detection groups --- */
.fpid{border:1px solid var(--line);background:var(--panel-2);padding:.6rem .9rem;margin:.7rem 0;font-size:.82rem;color:var(--muted);display:flex;flex-wrap:wrap;gap:.4rem 1.5rem}
.fpid .id-k{color:var(--muted);text-transform:uppercase;letter-spacing:.08em;font-size:.66rem}
.fpid b{color:var(--fox);font-variant-numeric:tabular-nums;font-weight:700}
.layer-group{margin:.5rem 0 1rem}
.layer-group .lg-head{display:flex;align-items:baseline;gap:.6rem;font-size:.74rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin:.6rem 0 .3rem}
.layer-group .lg-head .lg-fired{color:var(--fox);font-weight:700}
.passed-toggle{cursor:pointer;color:var(--muted);font-size:.76rem}
.passed-toggle summary{color:var(--jade)}
.passed-list{font-size:.74rem;color:var(--muted);columns:2;column-gap:2rem;margin:.3rem 0}
.passed-list code{color:var(--jade)}
.rule-link{text-decoration:none}.rule-link:hover code{text-decoration:underline}
.surface.pending{border-top-color:var(--line)}
.surface.pending .chip{color:var(--muted)}
.surface.pending .sval{color:var(--muted)}
/* --- overflow safety: let flex/grid children shrink + wrap long tokens (JA4/UA/hashes) --- */
html,body{overflow-x:hidden;max-width:100%}
.verdict,.coherence,.fpid,.bar,.hero,.layer-group{min-width:0}
.verdict>*,.coherence>*,.coherence .side,.fpid>*,.bar>*{min-width:0}
code,.sval,.shash,.title,.kv .v,.bar-label,.coherence .val,.fpid b{overflow-wrap:anywhere}
/* --- mobile (<=640px) --- */
@media (max-width:640px){
  nav.top,header,main,footer{padding-left:1rem;padding-right:1rem}
  nav.top{gap:.7rem .9rem}
  nav.top a{font-size:.72rem}
  nav.top a.brand{font-size:.85rem;letter-spacing:.16em}
  h1.page{font-size:1.4rem;letter-spacing:0}
  .lead{font-size:.95rem}
  .hero{gap:.9rem 1.5rem;padding:1rem}
  .hero-stat strong{font-size:1.8rem}
  .verdict{padding:1rem;gap:.5rem 1rem}
  .verdict .label{font-size:1.5rem}
  .verdict .sub{margin-left:0}
  .surfaces,.predict-grid,.bio-metrics{grid-template-columns:1fr}
  .coherence{grid-template-columns:1fr}
  .coherence .verdict-cell{border-left:0;border-right:0;border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:.5rem}
  .bar{grid-template-columns:5rem 1fr 2.25rem;gap:.5rem}
  .edge-list,.passed-list{columns:1}
  table.detections{font-size:.78rem}
  table.detections th:nth-child(3),table.detections td.weight{display:none}
  .fpid{gap:.3rem .9rem}
}
</style>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebApplication","name":"Kitsune","url":"https://kitsune.id/","applicationCategory":"SecurityApplication","operatingSystem":"Any","offers":{"@type":"Offer","price":"0","priceCurrency":"USD"},"description":"Antidetect & browser fingerprint test: cross-layer fingerprint, TLS/JA4, HTTP-2, QUIC, TCP/IP and bot detection."}</script>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"FAQPage","mainEntity":[{"@type":"Question","name":"What is a browser fingerprint?","acceptedAnswer":{"@type":"Answer","text":"The combination of signals a site reads from your browser — canvas/WebGL rendering, fonts, screen, audio, Client Hints and more — that together identify your device without cookies. Kitsune enumerates them and scores how coherent they are."}},{"@type":"Question","name":"Can antidetect browsers beat fingerprinting?","acceptedAnswer":{"@type":"Answer","text":"Stealth/antidetect browsers spoof many signals, but making every layer agree — TLS JA4, HTTP-2 frame order, TCP/IP stack, GPU renderer and the JS feature-set all consistent with one real device — is far harder. Kitsune flags the contradictions that remain."}},{"@type":"Question","name":"What is JA3 / JA4 TLS fingerprinting?","acceptedAnswer":{"@type":"Answer","text":"JA3 and JA4 fingerprint the TLS ClientHello your browser sends on connect. They identify the TLS stack, which often betrays an automation tool even when the User-Agent looks normal. Kitsune's edge reads yours from the raw connection."}},{"@type":"Question","name":"Is my browser detectable as a bot?","acceptedAnswer":{"@type":"Answer","text":"Run the test above: Kitsune scores your browser across network, browser, behavioral and reputation layers and returns a live verdict — human, suspicious, or bot — with the exact signals that fired."}},{"@type":"Question","name":"Does this send my data anywhere?","acceptedAnswer":{"@type":"Answer","text":"Your signals are scored by Kitsune's detector at this origin to produce the verdict. Raw captures stay on the host; only de-identified aggregates are ever shared. Nothing is sold or handed to third parties."}}]}</script>
</head>
<body>
<nav class="top">
  <a class="brand" href="/">Kitsune</a>
  <a href="/matrix">Matrix</a>
  <a href="/evasions">Evasions</a>
  <a href="/detections">Detections</a>
  <a href="/how-it-works">How it works</a>
  <a href="/research">Research</a>
  <a href="https://github.com/datascry/kitsune">GitHub</a>
  <span class="spacer"></span>
</nav>
<main>
<section id="test">
  <h1 class="page">Antidetect &amp; browser fingerprint test</h1>
  <p class="lead">Is your browser — or your stealth / antidetect setup — detectable? Kitsune fingerprints this browser across <strong>every layer — from the TLS handshake to the JavaScript</strong>, correlated at the edge, and returns the <strong>real bot-detection verdict</strong>, live.</p>
  <!-- HEADLINE: who you are + the verdict, together -->
  <div id="ks-fpid" class="fpid">computing your fingerprint…</div>
  <h2>Detector verdict</h2>
  <p id="ks-status">collecting…</p><div id="ks-result"></div>
  <!-- MACHINE-READABLE RESULT: automated tools can parse the verdict here without scraping the DOM.
       It starts as {"status":"collecting"} and is replaced with the full verdict (label, score,
       incoherence_score, layer_scores, contradictions[], session_id, and a wire{} block) once scoring
       completes — status becomes "complete". Also exposed as window.ksResult and a "kitsune:result"
       event. Poll this element's textContent, or: addEventListener("kitsune:result", e => e.detail). -->
  <script type="application/json" id="ks-verdict">{"status":"collecting"}</script>
  <div id="ks-coherence"></div>
  <!-- EVIDENCE: your fingerprint, layer by layer -->
  <div id="ks-predict"></div>
  <div id="ks-wire"></div>
  <div id="ks-surfaces"></div>
  <!-- INTERACT: behavioral panel AFTER the fingerprint surfaces (listeners arm on load regardless of order). -->
  <section id="ks-bio" aria-label="behavioral biometrics">
    <h2>Your behavioral biometrics</h2>
    <div id="ks-bio-metrics" class="bio-metrics">move your mouse, swipe, and type below to measure…</div>
    <p class="bio-help">Type a sentence below and move your mouse — or <b>swipe</b> on a touch screen — the detector measures your mouse/touch dynamics and keystroke timing live; it re-scores automatically once it has enough input (or press <b>Analyze</b>).</p>
    <input id="ks-bio-text" type="text" autocomplete="off" spellcheck="false" placeholder="Type a sentence here to measure keystroke timing…">
    <button type="button" id="ks-analyze">Analyze my behavior</button>
  </section>
  <!-- THE WHY: the full rule breakdown, after its evidence -->
  <h2>Detections <span class="note">— every check Kitsune ran, grouped by layer</span></h2>
  <div id="ks-detections"></div>
</section>
<section id="how-it-works">
  <h2>How Kitsune detects bots &amp; antidetect browsers</h2>
  <div class="prose">
    <p>Most fingerprint testers list signals. Kitsune flags <strong>incoherence across layers</strong> — the contradictions a real browser cannot produce but a spoofed or automated one does. The User-Agent, the TLS handshake, the HTTP-2 frames, the TCP/IP stack, the GPU and the JavaScript feature-set all have to describe <em>one</em> coherent device. When they disagree, that is the tell.</p>
    <p>It scores seven layers: <strong>TLS/JA4</strong>, <strong>HTTP-2</strong>, <strong>QUIC/HTTP-3</strong> and <strong>TCP/IP-OS</strong> read from the raw connection by Kitsune's edge; <strong>canvas, WebGL, audio, fonts and Client Hints</strong> in the browser; <strong>mouse and keystroke dynamics</strong>; and <strong>IP reputation</strong>. Every rule is data in a public registry — the same rules the server runs.</p>
    <p>An antidetect browser can spoof the User-Agent and patch <code>navigator.webdriver</code>, but making the JA4, the frame order, the TCP stack, the GPU renderer and the JS surface all agree on one real device is much harder — and that is exactly what this page measures.</p>
  </div>
</section>
<section id="faq" class="faq">
  <h2>FAQ</h2>
  <details><summary>What is a browser fingerprint?</summary><p>The combination of signals a site reads from your browser — canvas/WebGL rendering, fonts, screen, audio, Client Hints and more — that together identify your device without cookies. Kitsune enumerates them and scores how coherent they are.</p></details>
  <details><summary>Can antidetect browsers beat fingerprinting?</summary><p>Stealth/antidetect browsers (Camoufox, undetected-chromedriver, multilogin, …) spoof many signals, but making every layer agree — TLS JA4, HTTP-2 frame order, TCP/IP stack, GPU renderer and the JS feature-set all consistent with one real device — is far harder. Kitsune flags the contradictions that remain.</p></details>
  <details><summary>What is JA3 / JA4 TLS fingerprinting?</summary><p>JA3 and JA4 fingerprint the TLS ClientHello your browser sends on connect. They identify the TLS stack, which often betrays an automation tool even when the User-Agent looks normal. Kitsune's edge reads yours from the raw connection.</p></details>
  <details><summary>Is my browser detectable as a bot?</summary><p>Run the test above: Kitsune scores your browser across network, browser, behavioral and reputation layers and returns a live verdict — human, suspicious, or bot — with the exact signals that fired.</p></details>
  <details><summary>Does this send my data anywhere?</summary><p>Your signals are scored by Kitsune's detector at this origin to produce the verdict. Raw captures stay on the host; only de-identified aggregates are ever shared. Nothing is sold or handed to third parties.</p></details>
</main>
<footer><p>Your signals are scored by Kitsune's real detector at this origin — the blue-team side of a bot detection ⇄ evasion lab. Raw captures stay on the host; only de-identified verdicts are shared. <a href="https://github.com/datascry/kitsune">Source on GitHub</a>.</p>
<p class="note">IP geolocation by <a href="https://www.maxmind.com">GeoLite2 data created by MaxMind</a>.</p></footer>
<script>
(function () {
  function sid() { var m = document.cookie.match(/(?:^|; )ks_sid=([^;]+)/); return m ? decodeURIComponent(m[1]) : null; }
  function esc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
  // ---- client-side render: predicted browser, coherence, fingerprint surfaces, composite ID ----
  var KS_CONVICTING = { coherence: 1, automation: 1, artifact: 1 };
  var KS_RULES = null; // /rules.json (full evaluable registry), fetched once
  // One nonce per PAGE LOAD (this script runs once per load). Emitted with trace_hash so the detector
  // counts a replayed trajectory across distinct LOADS, not across this load's repeated re-score posts.
  var KS_LOAD = (function () { try { return crypto.randomUUID(); } catch (e) { return String(Math.random()).slice(2) + String(Math.random()).slice(2); } })();
  // Machine-readable result, mirrored into the #ks-verdict <script> tag + window.ksResult for scrapers.
  var KS_RESULT = { status: "collecting" };
  function publishResult(patch) {
    try {
      if (patch) { for (var k in patch) { if (Object.prototype.hasOwnProperty.call(patch, k)) KS_RESULT[k] = patch[k]; } }
      window.ksResult = KS_RESULT;
      var el = document.getElementById("ks-verdict");
      // textContent (not innerHTML) on an existing element isn't re-parsed; the \\u003c escape is belt-and-
      // braces so a serialize-then-reparse (outerHTML) of a contradiction detail can't close the tag.
      if (el) el.textContent = JSON.stringify(KS_RESULT).replace(/</g, "\\u003c");
      try { dispatchEvent(new CustomEvent("kitsune:result", { detail: KS_RESULT })); } catch (e) {}
    } catch (e) {}
  }
  function publishWire(d) {
    if (!d) return;
    var w = d.wire || {};
    publishResult({
      wire: { ip: d.ip || null, geo: d.geo || null, reputation: d.reputation || null, ja4: w.ja4 || null, ja3: w.ja3 || null, h2: w.h2 || null, tcp_os: w.tcp_os || null, quic: w.quic || null, wire_fp: d.wire_fp || null },
      network_contradictions: d.network_contradictions || []
    });
  }
  function fnv(s) { var h = 2166136261; for (var i = 0; i < s.length; i++) { h = ((h ^ s.charCodeAt(i)) * 16777619) >>> 0; } return (h >>> 0).toString(16); }
  function has(k) { return k in window; }
  function predictEngine(ev) {
    var gecko = false, webkit = false, blink = false;
    try { gecko = CSS.supports("-moz-appearance", "none") || has("InstallTrigger") || has("mozInnerScreenX") || typeof navigator.buildID === "string"; } catch (e) {}
    try { webkit = (has("GestureEvent") && !has("chrome")) || (CSS.supports("-webkit-touch-callout", "none") && !has("chrome") && !gecko); } catch (e) {}
    try { blink = has("chrome") || "userAgentData" in navigator || CSS.supports("-webkit-app-region", "drag"); } catch (e) {}
    if (gecko && !blink) { ev.push("CSS -moz-appearance / mozInnerScreenX / buildID"); return { engine: "gecko", confidence: 0.95 }; }
    if (blink && !gecko) { ev.push(has("chrome") ? "window.chrome present" : "navigator.userAgentData present"); return { engine: "blink", confidence: 0.95 }; }
    if (webkit) { ev.push("GestureEvent / -webkit-touch-callout, no chrome object"); return { engine: "webkit", confidence: 0.9 }; }
    ev.push("no decisive engine feature"); return { engine: "unknown", confidence: 0.3 };
  }
  function detectOsForm(ev) {
    var plat = (navigator.platform || "").toString(), touch = navigator.maxTouchPoints > 0 || has("ontouchstart"), ua = navigator.userAgent, os = "unknown", form = "unknown";
    if (/iPhone|iPad|iPod/.test(plat) || (plat === "MacIntel" && navigator.maxTouchPoints > 1)) { os = "iOS"; form = "mobile"; ev.push("iOS platform / touch-Mac"); }
    else if (/Mac/i.test(plat)) { os = "macOS"; form = "desktop"; }
    else if (/Win/i.test(plat)) { os = "Windows"; form = "desktop"; }
    else if (/Linux|Android|X11/i.test(plat)) {
      if (touch && Math.min(screen.width, screen.height) <= 600) { os = "Android"; form = "mobile"; ev.push("Linux platform + touch + small screen"); }
      else if (/Android/i.test(ua)) { os = "Android"; form = "mobile"; }
      else { os = "Linux"; form = "desktop"; }
    }
    return { os: os, formFactor: form };
  }
  function detectBrowser(engine, os, form, ev) {
    if (os === "iOS") { ev.push("iOS: all browsers share system WebKit"); return "iOS browser (WebKit)"; }
    if (engine === "gecko") return form === "mobile" ? "Firefox / GeckoView (Android)" : "Firefox";
    if (engine === "webkit") return "Safari";
    if (engine === "blink") {
      var mob = function (n) { return form === "mobile" ? n + " (Android)" : n; };
      if (has("opr") || has("opera")) { ev.push("window.opr (Opera)"); return mob("Opera"); }
      if ("brave" in navigator) { ev.push("navigator.brave (Brave)"); return mob("Brave"); }
      var brands = (navigator.userAgentData && navigator.userAgentData.brands) || [];
      var brand = brands.map(function (b) { return b.brand; }).join(" ");
      if (/Edg/i.test(brand)) { ev.push("UA-CH brand: Edge"); return mob("Edge"); }
      if (/Samsung/i.test(brand)) { ev.push("UA-CH brand: Samsung Internet"); return "Samsung Internet"; }
      if (/Google Chrome/i.test(brand)) { ev.push("UA-CH brand: Google Chrome"); return mob("Chrome"); }
      ev.push("Chromium engine, no vendor-specific global or UA-CH brand"); return mob("Chromium");
    }
    return "unknown";
  }
  function predict() { var ev = []; var e = predictEngine(ev); var of = detectOsForm(ev); var browser = detectBrowser(e.engine, of.os, of.formFactor, ev); return { engine: e.engine, browser: browser, os: of.os, formFactor: of.formFactor, confidence: e.confidence, evidence: ev }; }
  function uaClaimed() {
    var ua = navigator.userAgent, engine = "unknown", os = "unknown";
    if (/Firefox\\//.test(ua)) engine = "gecko"; else if (/Edg\\/|OPR\\/|Chrome\\//.test(ua)) engine = "blink"; else if (/Version\\/.*Safari\\//.test(ua)) engine = "webkit";
    if (/Android/.test(ua)) os = "Android"; else if (/iPhone|iPad|iPod/.test(ua)) os = "iOS"; else if (/Windows/.test(ua)) os = "Windows"; else if (/Macintosh|Mac OS X/.test(ua)) os = "macOS"; else if (/Linux|X11/.test(ua)) os = "Linux";
    return { engine: engine, os: os };
  }
  function coherence(p) {
    var c = uaClaimed();
    var engineOk = p.engine === "unknown" || c.engine === "unknown" || p.engine === c.engine;
    var osOk = p.os === "unknown" || c.os === "unknown" || p.os === c.os;
    var match = engineOk && osOk;
    var reason = match ? "feature prediction agrees with the User-Agent" : (!engineOk ? "features detect " + p.engine + ", but the UA claims " + c.engine : "features detect " + p.os + ", but the UA claims " + c.os);
    return { match: match, claimedEngine: c.engine, claimedOs: c.os, reason: reason };
  }
  function canvasHash() { try { var c = document.createElement("canvas"); c.width = 200; c.height = 40; var ctx = c.getContext("2d"); if (!ctx) return "n/a"; ctx.textBaseline = "top"; ctx.font = "16px Arial"; ctx.fillStyle = "#069"; ctx.fillRect(0, 0, 200, 40); ctx.fillStyle = "#f60"; ctx.fillText("Kitsune canvas \\u2728", 4, 4); return fnv(c.toDataURL()); } catch (e) { return "n/a"; } }
  function rawFingerprint() {
    var renderer = "n/a", vendor = "n/a";
    try { var gl = document.createElement("canvas").getContext("webgl"); var dbg = gl && gl.getExtension("WEBGL_debug_renderer_info"); if (gl && dbg) { renderer = String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)); vendor = String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)); } } catch (e) {}
    var tz = "n/a"; try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "n/a"; } catch (e) {}
    return {
      "User-Agent": navigator.userAgent,
      "navigator.platform": navigator.platform || "n/a",
      "navigator.vendor": navigator.vendor || "n/a",
      "Languages": (navigator.languages || []).join(", ") || "n/a",
      "Timezone": tz,
      "Screen": screen.width + "\\u00d7" + screen.height + " \\u00b7 DPR " + window.devicePixelRatio + " \\u00b7 " + screen.colorDepth + "-bit",
      "Hardware concurrency": String(navigator.hardwareConcurrency == null ? "n/a" : navigator.hardwareConcurrency),
      "Device memory": (navigator.deviceMemory != null ? navigator.deviceMemory + " GB" : "n/a"),
      "Max touch points": String(navigator.maxTouchPoints || 0),
      "WebGL vendor": vendor,
      "WebGL renderer": renderer
    };
  }
  function renderCoherence(p) {
    var el = document.getElementById("ks-coherence"); if (!el) return; var c = coherence(p);
    el.innerHTML = '<div class="coherence ' + (c.match ? "match" : "mismatch") + '">'
      + '<div class="side"><span class="cap">Feature prediction</span><span class="val">' + esc(p.engine) + ' \\u00b7 ' + esc(p.os) + '</span></div>'
      + '<div class="verdict-cell">' + (c.match ? "COHERENT" : "MISMATCH") + '</div>'
      + '<div class="side"><span class="cap">User-Agent claims</span><span class="val">' + esc(c.claimedEngine) + ' \\u00b7 ' + esc(c.claimedOs) + '</span></div>'
      + '</div><p class="note">' + esc(c.reason) + '</p>';
  }
  function renderPredict(p) {
    var el = document.getElementById("ks-predict"); if (!el) return;
    var kv = function (k, v) { return '<div class="kv"><span class="k">' + esc(k) + '</span><span class="v">' + esc(v) + '</span></div>'; };
    var ev = (p.evidence || []).map(function (x) { return '<li>' + esc(x) + '</li>'; }).join("");
    el.innerHTML = '<h2>Predicted browser <span class="note">\\u2014 from feature detection, independent of the User-Agent</span></h2>'
      + '<div class="predict-grid">' + kv("engine", p.engine) + kv("browser", p.browser) + kv("OS", p.os) + kv("form factor", p.formFactor) + kv("confidence", Math.round(p.confidence * 100) + "%") + '</div>'
      + '<details class="ev"><summary>feature evidence</summary><ul>' + ev + '</ul></details>';
  }
  // One panel = every fingerprint surface, each with its ENUMERATED values inline + its tamper status. This
  // is the consolidation of the old "Fingerprint surfaces" (value + tamper) and "Enumerated values" (a flat
  // key/value dump) panels — same detail, grouped by surface, no redundant second list. `keys` claims raw
  // rawFingerprint() fields; `extra()` adds computed rows (canvas/audio/realms have no single raw field); any
  // unclaimed field falls through to the "Other" catch-all so the panel never silently drops a value.
  var KS_SURFACES = [
    { name: "Navigator", keys: ["User-Agent", "navigator.platform", "navigator.vendor", "Languages", "Plugins", "Cookies / DNT", "UA-CH brands"], tells: ["webdriver", "webdriver_spoofed", "webdriver_getter_tampered", "nav_property_spoofed", "automation_globals"] },
    { name: "Client Hints", keys: ["CH platform", "CH architecture", "CH model", "CH full version"], tells: ["ch_he_headless", "ch_he_version_vs_ua"] },
    { name: "Display / screen", keys: ["Screen", "Color"], tells: ["color_depth_anomaly", "devicepixelratio_anomaly", "screen_zero"] },
    { name: "Hardware", keys: ["Hardware concurrency", "Device memory", "Max touch points", "Network"], tells: [] },
    { name: "WebGL", keys: ["WebGL vendor", "WebGL renderer"], tells: ["webgl_getparameter_tampered", "webgl_worker_divergence", "webgl_renderer_artifact"] },
    { name: "WebGPU", keys: ["WebGPU adapter", "WebGPU limits"], tells: ["webgpu_webgl_vs", "webgpu_vendor_vs_webgl"] },
    { name: "Canvas", extra: function () { return [["2D render hash", canvasHash()]]; }, tells: ["canvas_lie", "canvas_noise", "canvas_worker_divergence"] },
    { name: "Audio", keys: ["Audio"], tells: ["audio_noise", "audio_readback_noise"] },
    { name: "Fonts", keys: ["Fonts"], tells: ["font_os_vs_ua", "font_linux_leak", "font_mac_internal"] },
    { name: "Speech / media", keys: ["Speech voices", "Media devices"], tells: ["voices_empty", "voice_os_vs_ua"] },
    { name: "Timezone", keys: ["Timezone"], tells: ["timezone_inconsistent", "timezone_internal_incoherent", "timezone_worker_divergence"] },
    { name: "Functions", extra: function () { return [["integrity", "native (untampered)"]]; }, tells: ["native_invariant_violated", "function_tostring_tampered", "tostring_tampered", "plugins_spoofed"] },
    { name: "Workers / realms", extra: function () { return [["realms", "main vs Worker / iframe"]]; }, tells: ["worker_divergence", "iframe_divergence", "worker_constructor_tampered", "worker_source_rewritten", "languages_worker_divergence"] }
  ];
  function surfRow(k, v) { return '<div class="srow"><span class="sk">' + esc(k) + '</span><span class="sv">' + esc(v) + '</span></div>'; }
  function renderSurfaces(fp, firedSet) {
    var el = document.getElementById("ks-surfaces"); if (!el) return; firedSet = firedSet || {}; fp = fp || {};
    var cards = "", dirty = 0, claimed = {}, i, j;
    for (i = 0; i < KS_SURFACES.length; i++) {
      var s = KS_SURFACES[i], hit = [], rows = "", keys = s.keys || [];
      for (j = 0; j < s.tells.length; j++) { if (firedSet["br." + s.tells[j]]) hit.push(s.tells[j]); }
      for (j = 0; j < keys.length; j++) { claimed[keys[j]] = 1; if (fp.hasOwnProperty(keys[j])) rows += surfRow(keys[j], fp[keys[j]]); }
      if (s.extra) { var ex = s.extra(); for (j = 0; j < ex.length; j++) rows += surfRow(ex[j][0], ex[j][1]); }
      var tampered = hit.length > 0; if (tampered) dirty++;
      cards += '<div class="surface' + (tampered ? " tampered" : "") + '"><div class="top"><span class="sname">' + esc(s.name) + '</span><span class="chip">' + (tampered ? "tampered" : "clean") + '</span></div>' + rows + (tampered ? '<div class="stells">' + esc(hit.join(", ")) + '</div>' : "") + '</div>';
    }
    // Catch-all: any enumerated field no surface above claimed (keeps full detail as rawFingerprint grows).
    var other = "";
    for (var k in fp) { if (fp.hasOwnProperty(k) && !claimed[k]) other += surfRow(k, fp[k]); }
    if (other) cards += '<div class="surface"><div class="top"><span class="sname">Other</span><span class="chip">enumerated</span></div>' + other + '</div>';
    el.innerHTML = '<h2>Fingerprint surfaces <span class="note">\\u2014 enumerated values \\u00b7 tamper status (' + dirty + ' tampered)</span></h2><div class="surfaces">' + cards + '</div>';
  }
  // Offscreen font-presence probe: measure a string in OS-signature fonts vs the generic baselines; a width
  // change means the font is installed. Cheap, no canvas — surfaces the installed-font set as a value.
  function detectFonts() {
    try {
      if (!document.body) return [];
      var base = ["monospace", "sans-serif", "serif"];
      var probes = ["Segoe UI", "Calibri", "Cambria", "Tahoma", "Times New Roman", "Arial", "Helvetica Neue", "Menlo", "Monaco", "Geneva", "Roboto", "Noto Sans", "Ubuntu", "DejaVu Sans", "Liberation Sans", "Cantarell"];
      var span = document.createElement("span");
      span.style.cssText = "position:absolute;left:-9999px;top:-9999px;font-size:72px;line-height:normal";
      span.textContent = "mmmmmmmmmmlli\\u2014WX";
      document.body.appendChild(span);
      var baseW = {};
      for (var b = 0; b < base.length; b++) { span.style.fontFamily = base[b]; baseW[base[b]] = span.offsetWidth; }
      var found = [];
      for (var p = 0; p < probes.length; p++) {
        for (var b2 = 0; b2 < base.length; b2++) {
          span.style.fontFamily = "'" + probes[p] + "'," + base[b2];
          if (span.offsetWidth !== baseW[base[b2]]) { found.push(probes[p]); break; }
        }
      }
      document.body.removeChild(span);
      return found;
    } catch (e) { return []; }
  }
  // Enumerate the FULL set of profiled value-bearing surfaces (sync rawFingerprint + the async ones the
  // collector scores but the panel never showed: Client Hints high-entropy, WebGPU adapter/limits, audio FP,
  // installed fonts, speech voices, media-device counts, plugins, connection, colour capabilities), then
  // re-render the consolidated panel with it. Display-only — never blocks scoring; each probe is best-effort.
  async function enumerateSurfaces() {
    var fp = rawFingerprint();
    function set(k, v) { if (v != null && v !== "") fp[k] = String(v); }
    try { set("Plugins", ((navigator.plugins && navigator.plugins.length) || 0) + " plugin(s) \\u00b7 " + ((navigator.mimeTypes && navigator.mimeTypes.length) || 0) + " mimeType(s)" + (("pdfViewerEnabled" in navigator) ? " \\u00b7 pdf " + navigator.pdfViewerEnabled : "")); } catch (e) {}
    try { set("Cookies / DNT", "cookies " + (navigator.cookieEnabled ? "on" : "off") + " \\u00b7 DNT " + (navigator.doNotTrack || "unset")); } catch (e) {}
    try { var brands = (navigator.userAgentData && navigator.userAgentData.brands) || []; if (brands.length) set("UA-CH brands", brands.map(function (x) { return x.brand + " " + x.version; }).join(", ")); } catch (e) {}
    try { var gamut = matchMedia("(color-gamut: p3)").matches ? "p3" : (matchMedia("(color-gamut: srgb)").matches ? "srgb" : "?"); set("Color", (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light") + " \\u00b7 gamut " + gamut + " \\u00b7 " + (matchMedia("(prefers-reduced-motion: reduce)").matches ? "reduced-motion" : "full-motion")); } catch (e) {}
    try { var nc = navigator.connection; if (nc) set("Network", (nc.effectiveType || "?") + (nc.downlink != null ? " \\u00b7 " + nc.downlink + "Mbps" : "") + (nc.rtt != null ? " \\u00b7 " + nc.rtt + "ms" : "") + (nc.saveData ? " \\u00b7 saveData" : "")); } catch (e) {}
    try { var uad = navigator.userAgentData; if (uad && uad.getHighEntropyValues) { var he = await uad.getHighEntropyValues(["platform", "platformVersion", "architecture", "bitness", "model", "uaFullVersion"]); set("CH platform", (he.platform || "") + (he.platformVersion ? " " + he.platformVersion : "")); set("CH architecture", (he.architecture || "") + (he.bitness ? " " + he.bitness + "-bit" : "")); set("CH model", he.model); set("CH full version", he.uaFullVersion); } } catch (e) {}
    try { if (navigator.gpu && navigator.gpu.requestAdapter) { var ad = await navigator.gpu.requestAdapter(); if (ad) { var info = ad.info || (ad.requestAdapterInfo ? await ad.requestAdapterInfo() : null); var parts = []; if (info) { if (info.vendor) parts.push(info.vendor); if (info.architecture) parts.push(info.architecture); if (info.device) parts.push(info.device); } if (ad.isFallbackAdapter) parts.push("fallback"); set("WebGPU adapter", parts.length ? parts.join(" \\u00b7 ") : "adapter (no info)"); if (ad.limits) set("WebGPU limits", "maxTex " + ad.limits.maxTextureDimension2D + " \\u00b7 maxBuf " + ad.limits.maxBufferSize); } else set("WebGPU adapter", "no adapter"); } else set("WebGPU adapter", "absent"); } catch (e) {}
    try { var af = await audioFP(); set("Audio", (af && !af.missing) ? ("OfflineAudioContext \\u00b7 sum " + (typeof af.value === "number" ? af.value.toFixed(3) : "n/a") + (af.noise ? " (noised)" : "")) : "unavailable"); } catch (e) {}
    try { var ff = detectFonts(); set("Fonts", ff.length + " detected" + (ff.length ? " \\u00b7 " + ff.slice(0, 6).join(", ") : "")); } catch (e) {}
    try { var vs = (window.speechSynthesis && speechSynthesis.getVoices()) || []; if (!vs.length && _voices && _voices.length) vs = _voices; set("Speech voices", vs.length + " voice(s)" + (vs.length ? " \\u00b7 e.g. " + (vs[0].name || vs[0].lang || "") : "")); } catch (e) {}
    try { if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) { var devs = await navigator.mediaDevices.enumerateDevices(); var c = { audioinput: 0, videoinput: 0, audiooutput: 0 }; for (var i = 0; i < devs.length; i++) { if (c[devs[i].kind] != null) c[devs[i].kind]++; } set("Media devices", c.audioinput + " mic \\u00b7 " + c.videoinput + " cam \\u00b7 " + c.audiooutput + " out"); } } catch (e) {}
    window.__ksFpFull = fp;
    renderSurfaces(fp, window.__ksFiredSet || {});
  }
  function renderFpId(fp) {
    var el = document.getElementById("ks-fpid"); if (!el) return; var parts = [];
    for (var k in fp) { if (fp.hasOwnProperty(k)) parts.push(k + "=" + fp[k]); }
    var bh = fnv(parts.join("|")); window.__ksBrowserFp = bh;
    el.innerHTML = '<span><span class="id-k">browser fingerprint</span> <b>' + esc(bh) + '</b></span>'
      + '<span><span class="id-k">canvas</span> <b>' + esc(canvasHash()) + '</b></span>'
      + '<span><span class="id-k">full-stack id</span> <b title="browser \\u2295 wire \\u2014 needs the edge">pending edge</b></span>';
  }
  function ruleLink(id) { return '<a class="rule-link" href="/detections/' + encodeURIComponent(id) + '"><code>' + esc(id) + '</code></a>'; }
  function renderDetections(firedMap, firedCount) {
    if (!KS_RULES || !KS_RULES.rules) {
      if (!firedCount) return '<div class="na"><p>No convicting signals \\u2014 consistent with a real browser.</p></div>';
      var fh = '<table class="detections"><tr><th>signal</th><th>category</th><th>weight</th><th>why</th></tr>';
      for (var fid in firedMap) { if (firedMap.hasOwnProperty(fid)) { var fc = firedMap[fid]; fh += '<tr class="' + (KS_CONVICTING[fc.category] ? "fired" : "clear") + '"><td class="mark">' + ruleLink(fid) + '</td><td>' + esc(fc.category) + '</td><td class="weight">' + ((typeof fc.weight === "number") ? fc.weight.toFixed(2) : "") + '</td><td class="title">' + esc(fc.detail) + '</td></tr>'; } }
      return fh + '</table>';
    }
    var LAYERS = ["network", "browser", "behavioral", "reputation"], groups = { cross: [] }, rules = KS_RULES.rules, gi, k;
    for (gi = 0; gi < LAYERS.length; gi++) groups[LAYERS[gi]] = [];
    for (k = 0; k < rules.length; k++) { var r = rules[k]; var lay = (r.layers && r.layers.length > 1) ? "cross" : ((r.layers && r.layers[0]) || "browser"); if (!groups[lay]) groups[lay] = []; groups[lay].push(r); }
    var order = ["cross"].concat(LAYERS), out = '<p class="note">' + firedCount + ' signal(s) fired across ' + rules.length + ' checks \\u2014 only coherence / automation / artifact convict; the rest corroborate.</p>';
    for (gi = 0; gi < order.length; gi++) {
      var key = order[gi], grp = groups[key] || []; if (!grp.length) continue;
      var rows = "", passed = [], nFired = 0;
      for (k = 0; k < grp.length; k++) {
        var ru = grp[k], c = firedMap[ru.id];
        if (c) { nFired++; rows += '<tr class="' + (KS_CONVICTING[c.category] ? "fired" : "clear") + '"><td class="mark">' + ruleLink(ru.id) + '</td><td>' + esc(c.category) + '</td><td class="weight">' + ((typeof c.weight === "number") ? c.weight.toFixed(2) : "") + '</td><td class="title">' + esc(c.detail) + '</td></tr>'; }
        else passed.push(ru.id);
      }
      var title = key === "cross" ? "cross-layer" : key;
      out += '<div class="layer-group"><div class="lg-head">' + esc(title) + ' <span class="lg-fired">' + nFired + ' fired</span> <span>\\u00b7 ' + passed.length + ' passed</span></div>';
      out += rows ? ('<table class="detections"><tr><th>signal</th><th>category</th><th>weight</th><th>why</th></tr>' + rows + '</table>') : '<p class="note">none fired</p>';
      if (passed.length) { var pl = passed.map(function (x) { return ruleLink(x); }).join(" "); out += '<details class="passed-toggle"><summary>' + passed.length + ' checks passed</summary><div class="passed-list">' + pl + '</div></details>'; }
      out += '</div>';
    }
    return out;
  }
  function wireRow(name, val, note) {
    var present = !!val;
    return '<div class="surface' + (present ? "" : " pending") + '"><div class="top"><span class="sname">' + esc(name) + '</span><span class="chip">' + (present ? "captured" : "pending") + '</span></div><div class="sval">' + esc(present ? val : (note || "n/a")) + '</div></div>';
  }
  function renderWire(d) {
    var el = document.getElementById("ks-wire"); if (!el) return;
    if (!d) { el.innerHTML = '<h2>Network / wire layer <span class="note">\\u2014 captured by Kitsune\\u2019s edge</span></h2><p class="note">No edge session yet \\u2014 the wire layer (TLS/JA4, HTTP-2, TCP/IP, QUIC) is read from your raw connection when you reach this page through Kitsune\\u2019s edge.</p>'; return; }
    var w = d.wire || {}, g = d.geo || null, rep = d.reputation || null, ipLabel = d.ip || "";
    if (g) { var loc = [g.city, g.country].filter(function (x) { return x; }).join(", "); var org = g.asn_org || g.asn || ""; ipLabel = (d.ip || "") + (loc ? " \\u00b7 " + loc : "") + (org ? " \\u00b7 " + org : ""); }
    // IP reputation: datacenter/hosting + proxy/VPN/Tor-exit membership against the curated CIDR lists (the
    // same producer the rep.* rules use). A clean residential IP is shown as such, not left blank.
    var repLabel = "";
    if (rep) { var flags = []; if (rep.datacenter) flags.push("datacenter / hosting"); if (rep.proxy_exit) flags.push("proxy / VPN / Tor exit"); repLabel = flags.length ? flags.join(" \\u00b7 ") : "clean \\u2014 residential / unlisted"; }
    var cards = wireRow("IP / geo", ipLabel, "n/a") + wireRow("IP reputation", repLabel, d.ip ? "clean \\u2014 residential / unlisted" : "n/a")
      + wireRow("JA4 (TLS)", w.ja4, "n/a") + wireRow("JA3 (TLS)", w.ja3, "n/a")
      + wireRow("HTTP/2", w.h2, "n/a") + wireRow("TCP/IP OS", w.tcp_os, "n/a") + wireRow("QUIC / HTTP-3", w.quic, "captured on your next visit");
    var html = '<h2>Network / wire layer <span class="note">\\u2014 read from your raw connection by Kitsune\\u2019s edge</span></h2><div class="surfaces">' + cards + '</div>';
    var nc = d.network_contradictions || [];
    if (nc.length) {
      html += '<p class="note">' + nc.length + ' network/reputation signal(s) fired:</p><table class="detections"><tr><th>signal</th><th>category</th><th>why</th></tr>';
      for (var i = 0; i < nc.length; i++) { var c = nc[i]; html += '<tr class="' + (KS_CONVICTING[c.category] ? "fired" : "clear") + '"><td class="mark">' + ruleLink(c.rule_id) + '</td><td>' + esc(c.category) + '</td><td class="title">' + esc(c.detail) + '</td></tr>'; }
      html += '</table>';
    }
    el.innerHTML = html;
    // Full-stack fingerprint ID = browser FP \\u2295 wire FP — the cross-layer identifier a pure-JS tester can't form.
    if (d.wire_fp && window.__ksBrowserFp) {
      var full = fnv(window.__ksBrowserFp + "|" + d.wire_fp);
      var fpel = document.getElementById("ks-fpid");
      if (fpel) { var b = fpel.querySelectorAll("b"); if (b.length >= 3) { b[2].textContent = full; b[2].removeAttribute("title"); } }
    }
  }
  function fetchWire() {
    var id = sid(); if (!id) { renderWire(null); return; }
    try { fetch("/inspect/" + encodeURIComponent(id)).then(function (r) { return r.ok ? r.json() : null; }).then(function (d) { renderWire(d); publishWire(d); }).catch(function () { renderWire(null); }); } catch (e) { renderWire(null); }
  }
  function renderClientImmediate() {
    try {
      var p = predict(); window.__ksFp = rawFingerprint();
      renderFpId(window.__ksFp); renderCoherence(p); renderPredict(p); renderSurfaces(window.__ksFp, {});
      enumerateSurfaces();  // async: enrich the panel with every profiled value surface (CH/WebGPU/audio/fonts/voices/…)
      fetchWire();
    } catch (e) {}
  }
  // Close the detection loop for the visitor: render the REAL detector's verdict (the /ingest response).
  function showVerdict(v) {
    var status = document.getElementById("ks-status"), out = document.getElementById("ks-result");
    if (!v) { if (status) status.textContent = "no verdict (no session?)"; return; }
    if (status) status.textContent = "";
    var label = String(v.label || "?"), pct = Math.round((v.score || 0) * 100);
    var inc = Math.round((v.incoherence_score || 0) * 100);
    // Plain-English read of the verdict, instead of a bare second percentage.
    var explain;
    if (label === "human") explain = "Every layer agrees — consistent with a real browser.";
    else if (label === "bot") explain = inc > 0
      ? "Cross-layer contradiction: the layers describe different devices — a real browser can\\u2019t do that."
      : "A clear automation or spoofing artifact was found.";
    else explain = "Some signals don\\u2019t fit a coherent real browser, but there\\u2019s no hard bot signature.";
    var html = '<div class="verdict verdict-' + esc(label) + '">'
      + '<span class="label">' + esc(label.toUpperCase()) + '</span>'
      + '<span class="score">' + pct + '% bot-likelihood</span></div>'
      + '<p class="note">' + esc(explain) + '</p>';
    // Per-layer bars — how bot-like EACH layer looks (0 = human). The verdict is their combined
    // likelihood (not a sum), and a cross-layer contradiction counts toward it twice.
    var ls = v.layer_scores || {};
    var layers = ["network", "browser", "behavioral", "reputation"], bars = "";
    for (var li = 0; li < layers.length; li++) {
      var lp = Math.round((ls[layers[li]] || 0) * 100);
      bars += '<div class="bar' + (lp ? "" : " bar-clean") + '"><span class="bar-label">' + layers[li] + '</span>'
        + '<span class="bar-track"><span class="bar-fill" style="width:' + lp + '%"></span></span>'
        + '<span class="bar-val">' + lp + '</span></div>';
    }
    html += '<p class="note">How bot-like each layer looks — <b>0 is human</b>. The verdict combines them; '
      + 'a cross-layer contradiction (one device telling two stories) counts double'
      + (inc > 0 ? ' — yours is <b>' + inc + '%</b>' : '') + '.</p>';
    html += '<div class="layer-bars">' + bars + '</div>';
    if (out) out.innerHTML = html;  // #ks-result = the headline summary (verdict stamp + layer bars)
    // Publish the full verdict for automated consumers (the same fields the /ingest API returns).
    var rec = {}; for (var rk in v) { if (Object.prototype.hasOwnProperty.call(v, rk)) rec[rk] = v[rk]; }
    rec.status = "complete"; rec.session_id = sid();
    publishResult(rec);
    // The detailed layer-grouped detections render into their own section AFTER the evidence panels,
    // built from the full rule registry (/rules.json) cross-referenced with the fired contradictions.
    var cs = v.contradictions || [], firedMap = {}, firedSet = {};
    for (var i = 0; i < cs.length; i++) { firedMap[cs[i].rule_id] = cs[i]; firedSet[cs[i].rule_id] = 1; }
    window.__ksFiredSet = firedSet;  // remembered so an async surface re-render keeps tamper status
    var det = document.getElementById("ks-detections");
    if (det) det.innerHTML = renderDetections(firedMap, cs.length);
    // Surface tamper-state reflects which browser rules fired (from the server verdict).
    renderSurfaces(window.__ksFpFull || window.__ksFp || rawFingerprint(), firedSet);
    // Pull the edge wire layer (JA3/JA4/TCP-OS/QUIC + IP) for this session and form the full-stack ID.
    fetchWire();
  }
  // Fetch the full rule registry (for layer-grouped detections + the passed-checks list), then paint the
  // client-side panels immediately — predicted browser, coherence, surfaces, composite ID — independent of
  // the server verdict (which arrives after collection).
  try { fetch("/rules.json").then(function (r) { return r.json(); }).then(function (d) { KS_RULES = d; }).catch(function () {}); } catch (e) {}
  renderClientImmediate();
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
  var ptrMoves = 0, coalescedMax = 0, coalescedUntrusted = false;
  var coalescedSupported = typeof PointerEvent !== "undefined" && "getCoalescedEvents" in PointerEvent.prototype;
  if (coalescedSupported) {
    addEventListener("pointermove", function (e) {
      ptrMoves++;
      try {
        var c = e.getCoalescedEvents();
        if (c && c.length > coalescedMax) coalescedMax = c.length;
        // A real coalesced batch is the UA's OWN native samples — every entry isTrusted (hardware and even
        // CDP-dispatched events are trusted). A length>1 batch containing an UNTRUSTED (constructor-built) event
        // is fabricated: a getCoalescedEvents override faking coalescing to beat synthetic_no_coalesced, betrayed
        // by the injected events' isTrusted=false. Defeats Proxy-over-native — the Proxy keeps the function native
        // (toString/invariant clean) but cannot forge trusted DATA; new PointerEvent() is always untrusted.
        if (c && c.length > 1) {
          for (var ci = 0; ci < c.length; ci++) { if (c[ci] && c[ci].isTrusted === false) { coalescedUntrusted = true; break; } }
        }
      } catch (err) {}
    });
  }
  // Touch-swipe velocity uniformity (mobile biomech, radar X6) — grounded on BrainRun (161,780 real human
  // swipes: per-swipe velocity-CV median ~0.60, 1st-percentile 0.235). A human finger swipe has natural
  // speed variation; a synthetic/replayed swipe at near-constant velocity sits far below any human. Capture
  // per-swipe (one touch pointerdown→up), CV over the swipe's points (>=5); the session emits the MEDIAN
  // per-swipe CV. NB the mouse path-straightness floor is deliberately NOT ported to touch — real swipes are
  // inherently near-straight (median 0.993), so it would FP on >50% of users (see docs/mobile-biomech-grounding.md).
  // Captured via touch events (not pointer events): touchmove fires per native sample and touchend reliably
  // ends the swipe, whereas pointer events coalesce moves and can drop pointerup for synthetic/replayed touch.
  var swipeBuf = [], swipeForce = [], touchSwipeCVs = [], swipeStats = [];
  function _touchPt(e) { var t = (e.touches && e.touches[0]) || (e.changedTouches && e.changedTouches[0]); return t ? { x: t.clientX, y: t.clientY, t: e.timeStamp } : null; }
  function _touchForce(e) { var t = (e.touches && e.touches[0]) || (e.changedTouches && e.changedTouches[0]); return t && typeof t.force === "number" ? t.force : null; }
  addEventListener("touchstart", function (e) { var p = _touchPt(e); if (p) { swipeBuf = [p]; swipeForce = []; var f = _touchForce(e); if (f != null) swipeForce.push(f); } }, true);
  addEventListener("touchmove", function (e) { if (swipeBuf.length) { var p = _touchPt(e); if (p) swipeBuf.push(p); var f = _touchForce(e); if (f != null) swipeForce.push(f); } }, true);
  addEventListener("touchend", function (e) {
    if (swipeBuf.length >= 5) {
      // Reuse the desktop biomech extractors on the touch trajectory. Only velocity-CV CONVICTS (grounded
      // FP-safe on BrainRun, X6); duration/points/straightness/sub-movements/power-law are INFORMATIONAL —
      // the BrainRun analysis showed their human distributions overlap the bot region on touch (e.g. 15% of
      // real swipes have 0 sub-movements, β median ~0.16), so they are displayed but never convict.
      var cv = velcv(swipeBuf);
      if (cv >= 0) touchSwipeCVs.push(cv);
      swipeStats.push({
        cv: cv, npts: swipeBuf.length, dur: swipeBuf[swipeBuf.length - 1].t - swipeBuf[0].t,
        straight: straightness(swipeBuf), subs: submovementCount(swipeBuf), pl: powerLawExp(swipeBuf),
        force: swipeForce.length ? Math.max.apply(null, swipeForce) : null
      });
    }
    swipeBuf = []; swipeForce = [];
    try { renderBio(); } catch (x) {}
  }, true);
  // Teleport-click (FP-Agent's #1 AI-agent tell): a trusted, mouse-origin click (detail>=1) that lands with
  // ZERO pointer movement recorded in the whole session — a CDP/vision agent dispatching a click at target
  // coordinates without ever moving the cursor. Gates: detail>=1 excludes keyboard Enter/Space activation
  // (detail 0); maxTouchPoints==0 excludes a touch tap (fires click with no mousemove); zero total movement
  // is the bot-specific part — a real mouse cursor entering/jittering the page emits mousemove first.
  var teleportClick = false;
  addEventListener("click", function (e) {
    if (e.isTrusted && e.detail >= 1 && (navigator.maxTouchPoints || 0) === 0 && pts.length === 0 && ptrMoves === 0) teleportClick = true;
  }, true);
  // Keystroke timing: a real typist has variable inter-key intervals (digraph latencies differ); a script
  // that types at a fixed delay has near-zero interval entropy — the keystroke-dynamics tell.
  var keys = [];
  addEventListener("keydown", function (e) { keys.push(e.timeStamp); });
  // CSP-bypass probe: the page is served with `img-src 'self'`, so the `data:` bait below (data: is not
  // 'self') is blocked and fires securitypolicyviolation in a real browser. Playwright/Puppeteer scrapers that call
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
  // Honeypot bait: an element a human literally cannot reach — pushed off-screen, aria-hidden, and removed
  // from the tab order (tabIndex -1) — but a "click/fill everything" scraper or form-spammer enumerates the
  // DOM (querySelectorAll) and trips it. A click on the bait link, or a value typed into the bait input, is
  // a programmatic interaction no human pointer/keyboard can produce — an automation artifact, not a
  // behavioural measurement. Named like a real CTA/field ("Verify account" / "email_confirm") to tempt the
  // naive bot. Appended at DOMContentLoaded so it exists before the bot interacts and before send().
  var honeypotHit = false;
  var _hpInput = null;
  try {
    addEventListener("DOMContentLoaded", function () {
      try {
        var hw = document.createElement("div");
        hw.setAttribute("aria-hidden", "true");
        hw.style.cssText = "position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;";
        var a = document.createElement("a");
        // Fragment href: a DOM-enumerating scraper still clicks it (the click is the tell), but it never
        // navigates the document away, so the collector survives to report the hit. preventDefault belt-and-braces.
        a.id = "ks-hp"; a.href = "#"; a.tabIndex = -1; a.textContent = "Verify account";
        a.addEventListener("click", function (ev) { honeypotHit = true; try { ev.preventDefault(); } catch (x) {} });
        _hpInput = document.createElement("input");
        _hpInput.type = "text"; _hpInput.name = "email_confirm"; _hpInput.tabIndex = -1;
        _hpInput.setAttribute("autocomplete", "off");
        hw.appendChild(a); hw.appendChild(_hpInput);
        document.body.appendChild(hw);
      } catch (e) {}
    });
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
  // Median inter-keystroke interval (ms). Catches agent-speed typing that keeps human-like ENTROPY (varied
  // sub-ms gaps spread across log2 buckets) yet types far below any human cadence (Browser-Use ~5ms, Manus
  // ~1ms vs a human 100ms+). Orthogonal to keyEntropy, which only collapses for FIXED-delay scripts. Returns
  // -1 when there are too few intervals to judge (so the caller emits nothing, never a false floor hit).
  function keyIntervalMedian(ks) {
    var iv = [];
    for (var i = 1; i < ks.length; i++) { var dt = ks[i] - ks[i - 1]; if (dt > 0) iv.push(dt); }
    if (iv.length < 3) return -1;
    iv.sort(function (a, b) { return a - b; });
    return iv[Math.floor(iv.length / 2)];
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
      // getCoalescedEvents added (v0.74.36): a bot that fakes coalesced pointer batches to beat
      // bh.synthetic_no_coalesced (the COALESCE_SPOOF evader) overrides PointerEvent.prototype.getCoalescedEvents
      // with a non-native function — a real browser's is native. Catches that behavioural-residual spoof here.
      var fns = [Function.prototype.toString, HTMLCanvasElement.prototype.toDataURL,
                 HTMLCanvasElement.prototype.toBlob,
                 CanvasRenderingContext2D.prototype.getImageData,
                 navigator.permissions && navigator.permissions.query,
                 window.speechSynthesis && speechSynthesis.getVoices,
                 navigator.mediaDevices && navigator.mediaDevices.enumerateDevices,
                 (typeof PointerEvent !== "undefined") && PointerEvent.prototype.getCoalescedEvents];
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
        // The worker also reports its OWN self.location.href — for a real `new Worker(url)` that EQUALS the
        // blob URL the page passed. A tool that injects worker-scope spoofs (WORKER_WRAP / WORKER_PROXY /
        // the Proxy+constructor-fix escalation) must rewrite the source into a NEW blob, so the worker is
        // constructed from a DIFFERENT url → href != passed url. The data signature of worker-source rewriting,
        // robust no matter how the Worker constructor is disguised (the constructor-identity check can be
        // defeated by repairing prototype.constructor; the URL the worker actually loaded cannot be faked
        // without ALSO patching WorkerLocation in worker scope — a further, self-incriminating tamper).
        var code = 'onmessage=function(){postMessage({ua:navigator.userAgent,' +
          'hw:navigator.hardwareConcurrency,plat:navigator.platform||"",' +
          'lang:(navigator.languages||[]).join(","),href:self.location.href})}';
        var u = URL.createObjectURL(new Blob([code], { type: "application/javascript" }));
        var w = new Worker(u);
        var t = setTimeout(function () { resolve(null); }, 1500);
        w.onmessage = function (e) {
          clearTimeout(t);
          var d = e.data || {};
          d.expectedHref = u;
          resolve(d);
          w.terminate();
        };
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
    // Brave identity (the definitive navigator.brave global — Brave's UA is plain Chrome). Context only, not
    // a tell: the scorer uses it to mark Brave's BY-DESIGN canvas/audio farbling (canvas_noise/audio_noise)
    // as expected, so a real Brave user is not convicted on its privacy feature. A Brave-faking bot still
    // trips webdriver/CDP/etc., so this cannot help a bot escape.
    if (navigator.brave) {
      sigs.push(S("browser", "is_brave", true));
      // A real Brave's navigator.brave.isBrave is a NATIVE function AND navigator.brave is a genuine platform
      // object (the Web IDL `Brave` interface — its [[Prototype]] is the Brave interface prototype). A bot that
      // injects navigator.brave to exploit the privacy-browser farbling N/A lives on a PLAIN `{isBrave}` object
      // whose prototype IS Object.prototype — whether isBrave is a plain function (toString != "[native code]")
      // OR a `new Proxy(nativeFn, {apply})` that REFLECTS the native "[native code]" toString (defeating the
      // shallow check alone). The plain-object check catches the Proxy escalation the toString check misses; a
      // real Brave is never a plain object, so it stays exempt (FP-safe).
      try {
        var _ib = navigator.brave.isBrave;
        if (typeof _ib !== "function" || _ib.toString().indexOf("[native code]") < 0 ||
            Object.getPrototypeOf(navigator.brave) === Object.prototype)
          sigs.push(S("browser", "brave_spoofed", true));
      } catch (e) { sigs.push(S("browser", "brave_spoofed", true)); }
    }
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
    // The GPU API in the renderer string implies an OS — but ONLY for the OS-exclusive stacks: Direct3D is
    // Windows-only (ANGLE D3D backend), Metal/Apple is macOS-only, Mesa/GLX are Linux/X11 stacks Windows/macOS
    // never use. Vulkan/OpenGL/SwiftShader/llvmpipe are CROSS-PLATFORM (a real Windows/macOS browser reports
    // them too, via a non-default ANGLE backend or software rendering on a VM/RDP/GPU-blacklisted host), so
    // they imply NO OS — mapping them to Linux false-fired webgl_os_vs_ua on real software-rendering users.
    var wo = /Direct3D|D3D[0-9]/i.test(wg.renderer) ? "Windows"
           : /Metal|Apple/i.test(wg.renderer) ? "macOS"
           : /Mesa|GLX/i.test(wg.renderer) ? "Linux" : "";
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
      function ctorTampered(c) {
        if (typeof c !== "function") return false;
        if (c.toString().indexOf("[native code]") < 0) return true; // plain-function wrap (WORKER_WRAP)
        // Proxy-over-native escalation (WORKER_PROXY): a `new Proxy(Worker, {construct})` REFLECTS the native
        // target's toString → "[native code]" (so the check above misses it) but cannot preserve the
        // constructor-identity round-trip. A real native ctor satisfies C.prototype.constructor === C; a Proxy's
        // .prototype forwards to the REAL ctor's prototype whose .constructor is the real ctor, not the Proxy →
        // identity breaks. FP-safe by spec (every native constructor's prototype.constructor is itself).
        try { if (c.prototype && c.prototype.constructor !== c) return true; } catch (e) { return true; }
        return false;
      }
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
    // DOMRect determinism: on a real engine two reads of an unchanged element are byte-identical (pages
    // depend on it), and a per-call DOMRect-noise shim (the DOMRECT_SPOOF evader) breaks it — the grounded
    // tell. The old getClientRects()[0]-vs-getBoundingClientRect() *consistency* arm was removed: real
    // Safari on a Retina display rounds the two geometry paths to sub-pixel-different values, a legitimate
    // engine difference that false-positived real Safari, and no evader ever exercised that arm.
    try {
      var dre = document.createElement("div");
      dre.style.cssText = "position:absolute;left:-9999px;top:0;width:123.45px;height:67.8px;transform:rotate(7deg) scale(1.3)";
      dre.textContent = "x";
      document.documentElement.appendChild(dre);
      var dra = dre.getBoundingClientRect(), drc = dre.getBoundingClientRect();
      var drDet = dra.x === drc.x && dra.y === drc.y && dra.width === drc.width && dra.height === drc.height;
      document.documentElement.removeChild(dre);
      if (!drDet) sigs.push(S("browser", "domrect_invariant_violated", true));
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
    // no_plugins / mimetypes_empty / chrome_no_pdfviewer are DESKTOP tells: a real desktop browser ships a
    // standardized 5 plugins / 2 mimeTypes / pdfViewerEnabled=true, so a zero there is a stripped-browser
    // signature. But every real MOBILE browser (Android Chrome, iOS Safari) legitimately reports 0 plugins,
    // 0 mimeTypes, and no PDF viewer — so on mobile these would false-fire on every real user (browserforge:
    // 98% of Android). Gate their emission to non-mobile so they fire only where zero is genuinely anomalous.
    var isMobileEnv = /Mobile|Android|iPhone|iPad/i.test(ua);
    if (!isMobileEnv)
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
    // vendor_engine drives br.vendor_vs_ua. Abstain (don't emit) in two cases: (1) iOS — Apple forces WebKit
    // for EVERY browser but navigator.vendor follows the BRAND (Chrome-iOS/CriOS reports "Google Inc." on
    // WebKit; in-app WebViews report "Apple…"), so the vendor and UA-engine axes decouple legitimately
    // (grounded on Intoli: 122/10000 iOS FPs); (2) uaEngine "other" — an unclassifiable UA (a bare
    // "AppleWebKit (KHTML, like Gecko)" macOS WKWebView with no browser token), where comparing vendor
    // against an UNKNOWN engine would convict on "unknown" (unknown never fires). A classifiable engine still
    // fires (a macOS Safari UA reporting vendor "Google Inc." stays uaEngine=safari → caught). An iOS UA-spoof
    // on a Chromium host is still caught by apple_ua_nonwebkit (window.chrome/userAgentData).
    var isIOS = /iPhone|iPad|iPod/i.test(ua);
    if (!isIOS && uaEngine !== "other") sigs.push(S("browser", "vendor_engine", venEngine));
    // Error.stackTraceLimit is a NUMBER on V8 (Chromium, default 10) but does NOT exist on SpiderMonkey or
    // JSC (undefined). So a UA claiming Chrome without it, or claiming Firefox WITH it, is an engine spoof
    // deeper than navigator.vendor (which JS-stealth tools patch, while the V8 Error-API surface they often
    // miss). v0.74.27: the discriminator was Error.captureStackTrace, but SpiderMonkey ADDED that natively in
    // Firefox 122 (Jan 2024) — GROUNDED on stock Firefox 152 AND a real Mullvad Browser 140, both report
    // typeof Error.captureStackTrace === "function" — so the old check false-fired the firefox arm on EVERY
    // modern real Firefox/Tor/Mullvad (a convicting coherence FP). Error.stackTraceLimit stays V8-exclusive
    // (grounded: Chromium === "number" 10, stock Firefox 152 === undefined, JSC has none), so it fixes the FP
    // while PRESERVING both spoof directions (a V8 engine faking Firefox still has it; a non-V8 faking Chrome
    // still lacks it). NOTE: not Safari-exclusive in reverse — apple_ua_nonwebkit covers the WebKit side.
    var hasV8Stack = typeof Error.stackTraceLimit === "number";
    if ((uaEngine === "chromium" && !hasV8Stack) || (uaEngine === "firefox" && hasV8Stack))
      sigs.push(S("browser", "engine_stack_mismatch", true));
    // Apple mandates WebKit for Safari AND every iOS browser — Chrome (CriOS), Firefox (FxiOS), Brave,
    // DuckDuckGo, Onion all wrap the system WebKit, none ship Blink. So a UA claiming Apple WebKit (a Safari
    // token with no desktop-Chromium token → uaEngine "safari") that exposes a Blink-ONLY structural API is
    // impossible on a real Apple browser: window.chrome and navigator.userAgentData (UA-CH, unimplemented in
    // any Safari) never exist there → a Chromium host faking an iOS/Safari UA. STRUCTURAL (positive-API, not
    // error-message/float based) so it survives the message and math spoofs error_engine/math_engine rely on.
    // v0.74.9: the V8 Error.captureStackTrace arm was REMOVED — JSC added captureStackTrace in Safari 16.4
    // (grounded on a live WebKit 18.4 engine that exposes it while correctly lacking window.chrome /
    // userAgentData), so the old arm convicted every real Safari 16.4+/iOS user. window.chrome and
    // userAgentData remain genuinely Blink-only (absent in every Safari), so the spoof catch is preserved.
    if (uaEngine === "safari" && (window.chrome || navigator.userAgentData))
      sigs.push(S("browser", "apple_ua_nonwebkit", true));
    // Gecko analog of apple_ua_nonwebkit: navigator.buildID is a Gecko-ONLY surface. Every real Firefox
    // (and every Gecko browser: Tor, Mullvad, LibreWolf, ESR/Nightly) exposes it — release builds freeze it
    // to "20181001000000" for anti-fingerprinting, but it is always a present non-empty string. Blink and
    // WebKit have no navigator.buildID at all (verified: a live Chromium/WebKit reports undefined). So a UA
    // claiming Firefox (uaEngine "firefox") with NO buildID is a non-Gecko engine (Chromium/WebKit) faking a
    // Firefox UA. STRUCTURAL positive-surface tell, complementary to engine_stack_vs_ua: a spoof that deletes
    // Error.captureStackTrace to beat engine_stack still cannot synthesise a real Gecko buildID surface.
    if (uaEngine === "firefox" && (typeof navigator.buildID !== "string" || !navigator.buildID))
      sigs.push(S("browser", "firefox_ua_nongecko", true));
    // WebKit analog (negative-surface complement to apple_ua_nonwebkit): window.GestureEvent is a
    // WebKit-ONLY global (the multi-touch gesture API, in every desktop + iOS Safari since Safari 5). Blink
    // and Gecko have no GestureEvent (verified: a live Chromium/Firefox reports undefined, a live WebKit
    // reports "function"). So a UA claiming Safari (uaEngine "safari") WITHOUT window.GestureEvent is a
    // non-WebKit engine faking Safari — and unlike apple_ua_nonwebkit (which keys on Blink APIs PRESENT), a
    // spoof that DELETES window.chrome/userAgentData to beat that rule still cannot synthesise GestureEvent.
    if (uaEngine === "safari" && typeof window.GestureEvent !== "function")
      sigs.push(S("browser", "safari_ua_no_webkit_api", true));
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
    // (Removed v0.74.0) The Math.pow(PI,-100) last-ULP engine tell was RETIRED: it is NOT engine-stable —
    // it is V8-build/CPU-dependent (node 22 → ...204e-50, Playwright Chromium → ...206e-50), so it
    // false-fired on a real Chromium. Engine coherence is covered by engine_stack_vs_ua / error_engine_vs_ua
    // / vendor_vs_ua / apple_ua_nonwebkit (hard, reliable channels). See br.math_engine_vs_ua in the registry.
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
    // Spec invariant: navigator.language IS navigator.languages[0] (HTML standard). A real browser can never
    // disagree — the only way to make them differ is a sloppy JS locale spoof (a residential-proxy geo-spoof
    // that Object.defineProperty's navigator.language to the proxy's country but leaves navigator.languages).
    // Self-contained (no Worker, no HTTP/IP-geo); FP-safe by spec.
    var _l0 = navigator.languages && navigator.languages[0];
    if (navigator.language && _l0 && navigator.language !== _l0)
      sigs.push(S("browser", "language_list_incoherent", true));
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
    if (isChromium && !isMobileEnv && navigator.pdfViewerEnabled === false) sigs.push(S("browser", "chrome_no_pdfviewer", true));
    if (window.chrome && !window.chrome.runtime) sigs.push(S("browser", "chrome_runtime_missing", true));
    if (navigator.maxTouchPoints > 0 && !/Mobile|Android|iPhone|iPad/i.test(ua)) sigs.push(S("browser", "maxtouch_desktop", true));
    // Spatial UA<->capability coherence (FP-Inconsistent, ACM IMC 2025): a phone/tablet UA is a touchscreen
    // device — every real one reports navigator.maxTouchPoints > 0 (iOS Safari = 5, Android > 0). A mobile UA
    // with maxTouchPoints === 0 is a desktop wearing a mobile UA without touch emulation (CDP setUserAgent to
    // a phone UA but no Emulation.setTouchEmulation). Scoped to the Mobile/iPhone/iPad tokens, NOT bare
    // "Android" (which also matches touch-less Android TV / Auto). Complements maxtouch_desktop (the inverse).
    if ((navigator.maxTouchPoints || 0) === 0 && /iPhone|iPad|iPod|Mobile/i.test(ua)) sigs.push(S("browser", "mobile_no_touch", true));
    // Genuine mobile device = a mobile UA token AND real touch. The detector gates the mouse-biomech
    // behavioral FLOORS off for these (power-law / straightness / velocity-CV / mouse-entropy / coalesced-
    // absent are mouse-calibrated and false-positive on a real finger swipe — G10). NOT set for a mobile UA
    // without touch (that is mobile_no_touch, a desktop faker). trace_replay stays active (device-agnostic).
    if (navigator.maxTouchPoints > 0 && /Mobile|Android|iPhone|iPad/i.test(ua)) sigs.push(S("browser", "is_mobile", true));
    if (!isMobileEnv && navigator.mimeTypes && navigator.mimeTypes.length === 0) sigs.push(S("browser", "mimetypes_empty", true));
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
    var autoGlobals = ["Buffer", "process", "global", "require", "__playwright__", "__playwright__binding__",
      "__pw_manual", "__puppeteer_evaluation_script__", "__puppeteer__", "_playwright", "fmget_targets"];
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
        // Re-read at send time: some real browsers populate voices async WITHOUT firing onvoiceschanged,
        // so the arm-time grab can be stale-empty. Freshest getVoices() avoids a spurious voices_empty FP.
        var _latest = speechSynthesis.getVoices() || [];
        if (_latest.length > 0) _voices = _latest;
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
        // IDENTICAL: it forces the timezone to UTC, letterboxes the content window to 200x100 multiples, and
        // generalises the WebGL UNMASKED vendor AND renderer to literally "Mozilla" (an RFP-exclusive string
        // — a normal browser reports the real GPU or "llvmpipe, or similar"). Each trait alone is common (a
        // UK user, a round window); together they are the RFP signature — require the conjunction, not any
        // one. v0.74.26 (GROUNDED on a real Mullvad Browser 15.0.16, corpus/calibration/privacy/mullvad.json):
        // the RELIABLE, RFP-EXCLUSIVE tell is rfpGL — RFP generalises BOTH the WebGL UNMASKED vendor and
        // renderer to literally "Mozilla", which no normal browser reports. It is required. The legacy legs
        // are NOT: hardwareConcurrency<=2 is stale (modern Tor/Mullvad report 4), and the letterbox check is
        // TIMING-FLAKY (RFP applies the 200x100 letterboxing AFTER the collector's early inline run, so
        // innerHeight is not yet a clean multiple at probe time). So rfpGL is the gate and any ONE common RFP
        // trait (UTC tz / letterboxed window / 2-core clamp) corroborates — rfpGL being RFP-exclusive means
        // the corroborators cannot cause a false identification on a non-RFP browser.
        var rfpUTC = tz === "UTC";
        var rfpBox = window.innerWidth > 0 && window.innerWidth % 200 === 0 && window.innerHeight % 100 === 0;
        var rfpCores = (navigator.hardwareConcurrency || 99) <= 2;
        var rfpGL = wg.renderer === "Mozilla" && wg.vendor === "Mozilla";
        if (rfpGL && (rfpUTC || rfpBox || rfpCores)) sigs.push(S("browser", "rfp_browser", true));
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
    // Worker source-URL coherence: a real `new Worker(url)` runs in a global whose self.location.href EQUALS
    // the blob URL the page passed; a tool injecting worker-scope spoofs must rewrite the source into a new
    // blob → href differs. The data signature of worker-source rewriting, robust to any constructor disguise
    // (Proxy, prototype.constructor repair) — the injection cannot keep the same URL while changing the code.
    if (wn && wn.href && wn.expectedHref && wn.href !== wn.expectedHref) {
      sigs.push(S("browser", "worker_source_rewritten", true));
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
    // Honeypot: a click on the off-screen aria-hidden bait link, or a value typed into the hidden bait
    // input, is a programmatic DOM-enumeration interaction no human can perform. Emitted in every mode
    // (an automation artifact, not behaviour); conservative — fires ONLY on a definitive hit, never on absence.
    if (honeypotHit || (_hpInput && _hpInput.value !== "")) sigs.push(S("browser", "honeypot_interacted", true));
    // In `?fast` (detection-only) captures we don't simulate input, so emitting empty behavioral
    // signals would make the *absence* of input score as bot-like and mask the fingerprint result.
    // Omit the behavioral layer entirely in fast mode; a full capture still scores behaviour.
    if (!/(?:\\?|&)fast\\b/.test(location.search)) {
      // Don't penalise a real visitor who simply hasn't moved/typed yet. Emit the behavioral layer ONLY
      // once there is enough genuine human input to expect human structure (>=12 pointer samples — the
      // Balabit min segment length — or >=4 keystrokes). Below that, emit NOTHING behavioral so an
      // undersampled trace scores neutral, not bot-like; the page auto-re-scores once real input arrives.
      if (pts.length >= 12) {
        sigs.push(S("behavioral", "mouse_entropy", entropy(pts)));
        sigs.push(S("behavioral", "pointer_event_count", pts.length));
        sigs.push(S("behavioral", "mouse_straightness", straightness(pts)));
        sigs.push(S("behavioral", "mouse_velocity_cv", velcv(pts)));
        // Biomechanics: corrective sub-movements, pauses, and the 2/3 power law — a Bezier humanizer does
        // none of these (docs/behavioral-data.md).
        sigs.push(S("behavioral", "submovement_count", submovementCount(pts)));
        sigs.push(S("behavioral", "pause_ratio", pauseRatio(pts)));
        var ple = powerLawExp(pts);
        if (ple !== null) sigs.push(S("behavioral", "power_law_exponent", ple));
        var th = traceHash(pts);
        // Pair the trajectory hash with this load's nonce so re-scoring the same path in ONE load can't
        // self-collide into a false "record-and-replay" verdict (only a recurrence across loads counts).
        if (th !== null) { sigs.push(S("behavioral", "trace_hash", th)); sigs.push(S("behavioral", "load_nonce", KS_LOAD)); }
        // Enough of a pointer stream to expect coalescing on real hardware, yet none ever occurred.
        if (coalescedSupported && ptrMoves >= 20 && coalescedMax <= 1) {
          sigs.push(S("behavioral", "coalesced_events_absent", true));
        }
      }
      if (keys.length >= 4) {
        sigs.push(S("behavioral", "keystroke_entropy", keyEntropy(keys)));
        var kim = keyIntervalMedian(keys);  // agent-speed-typing tell, orthogonal to entropy (radar G13)
        if (kim >= 0) {
          sigs.push(S("behavioral", "keystroke_interval_ms", kim));
          // Mobile-aware floor (radar X6): a MOBILE session typing faster than ~80ms/key is non-human —
          // real mobile typing's per-session median inter-key is far slower (Aalto ITE: p1 118ms; only
          // 0.018% of 850k sessions median <80ms). Catches a bot typing at DESKTOP speed (30-80ms) on a
          // mobile session, which the universal 30ms floor misses. Emitted only on mobile -> self-gating.
          if (navigator.maxTouchPoints > 0 && /Mobile|Android|iPhone|iPad/i.test(navigator.userAgent))
            sigs.push(S("behavioral", "mobile_keystroke_interval_ms", kim));
        }
      }
      if (teleportClick) sigs.push(S("behavioral", "click_without_trajectory", true));  // radar G11
      if (touchSwipeCVs.length) {  // mobile touch-swipe velocity uniformity (radar X6, BrainRun-grounded)
        touchSwipeCVs.sort(function (a, b) { return a - b; });
        sigs.push(S("behavioral", "touch_velocity_cv", touchSwipeCVs[Math.floor(touchSwipeCVs.length / 2)]));
      }
      // A coalesced batch carrying an untrusted (constructor-built) event is fabricated — a hard artifact a
      // real browser never produces, even through a Proxy-over-native override. Always emitted (an artifact).
      if (coalescedUntrusted) sigs.push(S("browser", "coalesced_untrusted", true));
    }
    fetch("/ingest", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sigs) })
      .then(function (r) { return r.json(); })
      .then(function (list) {
        document.body.setAttribute("data-ks", "sent");
        showVerdict(list && list.length ? list[list.length - 1] : null);
      })
      .catch(function () { document.body.setAttribute("data-ks", "sent"); });
  }
  // Default 1200ms lets behavioral (mouse) signals accumulate. `?fast` cuts the wait for
  // detection-only captures that need the browser-layer fingerprint, not behaviour (e.g. the
  // single-Camoufox frontier test); body[data-ks=sent] lets a harness wait on completion.
  // Interactive biometrics: a live readout (near the top) computed from the SAME pts/keys the detector
  // scores, plus buttons + a text input that elicit real mouse dynamics and keystroke timing. The global
  // mousemove/keydown listeners above already capture interaction anywhere on the page (the text input's
  // keydowns bubble to window), so the panel just drives richer input and lets the visitor re-score it.
  function bioRow(label, val, cls) { return '<div class="bio-row"><span>' + label + '</span><b>' + val + '</b><i class="bm-' + cls + '">' + cls + '</i></div>'; }
  function bioHead(label) { return '<div class="bio-head">' + label + '</div>'; }
  function renderBio() {
    var el = document.getElementById("ks-bio-metrics");
    if (!el) return;
    // Grouped DESKTOP (mouse) / MOBILE (touch) / KEYSTROKE (both). Every metric is always shown — greyed
    // "collecting" until it has enough samples — so nothing is hidden behind a status tag.
    var enoughPts = pts.length >= 3, fullPts = pts.length >= 12, enoughKeys = keys.length >= 4;
    var isMob = (navigator.maxTouchPoints > 0) && /Mobile|Android|iPhone|iPad/i.test(navigator.userAgent);
    function _med(a) { if (!a.length) return null; var s = a.slice().sort(function (x, y) { return x - y; }); return s[Math.floor(s.length / 2)]; }

    // --- Desktop · mouse (mouse-calibrated; gated off mobile by the detector, G10) ---
    var rows = bioHead("Desktop \\u00b7 mouse");
    rows += bioRow("pointer events", pts.length, fullPts ? "ok" : "collecting");
    rows += bioRow("mouse entropy", enoughPts ? entropy(pts).toFixed(3) : "\\u2014", enoughPts ? (entropy(pts) < 0.15 ? "bot" : "human") : "collecting");
    rows += bioRow("path straightness", enoughPts ? straightness(pts).toFixed(3) : "\\u2014", enoughPts ? (straightness(pts) > 0.97 ? "bot" : "human") : "collecting");
    rows += bioRow("velocity CV", enoughPts ? velcv(pts).toFixed(3) : "\\u2014", enoughPts ? (velcv(pts) < 0.08 ? "bot" : "human") : "collecting");
    var ple = fullPts ? powerLawExp(pts) : null;
    rows += bioRow("power-law \\u03b2", ple !== null ? ple.toFixed(3) : "\\u2014", ple !== null ? (ple < 0.05 ? "bot" : "human") : "collecting");

    // --- Mobile · touch (only swipe velocity CV convicts, BrainRun-grounded; the rest are informational) ---
    rows += bioHead("Mobile \\u00b7 touch");
    var medSwipe = -1;
    if (touchSwipeCVs.length) { var sc = touchSwipeCVs.slice().sort(function (a, b) { return a - b; }); medSwipe = sc[Math.floor(sc.length / 2)]; }
    rows += bioRow("swipe velocity CV", medSwipe >= 0 ? medSwipe.toFixed(3) : "\\u2014", medSwipe >= 0 ? (medSwipe < 0.15 ? "bot" : "human") : "collecting");
    var haveSw = swipeStats.length > 0, infoCls = haveSw ? "measured" : "collecting";
    var swDur = _med(swipeStats.map(function (s) { return s.dur; }));
    var swPts = _med(swipeStats.map(function (s) { return s.npts; }));
    var swStr = _med(swipeStats.map(function (s) { return s.straight; }));
    var swSub = _med(swipeStats.map(function (s) { return s.subs; }));
    var plVals = swipeStats.map(function (s) { return s.pl; }).filter(function (v) { return v !== null; }), swPl = _med(plVals);
    var forces = swipeStats.map(function (s) { return s.force; }).filter(function (f) { return f != null && f > 0; }), swForce = _med(forces);
    rows += bioRow("swipe duration (ms)", swDur != null ? Math.round(swDur) : "\\u2014", infoCls);
    rows += bioRow("points / swipe", swPts != null ? swPts : "\\u2014", infoCls);
    rows += bioRow("swipe straightness", swStr != null ? swStr.toFixed(3) : "\\u2014", infoCls);
    rows += bioRow("swipe sub-movements", swSub != null ? swSub : "\\u2014", infoCls);
    rows += bioRow("swipe power-law \\u03b2", swPl != null ? swPl.toFixed(3) : "\\u2014", infoCls);
    rows += bioRow("touch pressure", swForce != null ? swForce.toFixed(2) : "\\u2014", forces.length ? "measured" : (haveSw ? "na" : "collecting"));

    // --- Keystroke · both (device-agnostic; the inter-key floor is mobile-aware: 80ms on mobile, 30ms desktop) ---
    rows += bioHead("Keystroke \\u00b7 both");
    rows += bioRow("keystrokes", keys.length, enoughKeys ? "ok" : "collecting");
    rows += bioRow("keystroke entropy", enoughKeys ? keyEntropy(keys).toFixed(3) : "\\u2014", enoughKeys ? (keyEntropy(keys) < 0.15 ? "bot" : "human") : "collecting");
    var kim = enoughKeys ? keyIntervalMedian(keys) : -1, kFloor = isMob ? 80 : 30;
    rows += bioRow("inter-key interval (ms)" + (isMob ? " \\u00b7 mobile" : ""), kim >= 0 ? Math.round(kim) : "\\u2014", kim >= 0 ? (kim < kFloor ? "bot" : "human") : "collecting");
    el.innerHTML = rows;
  }
  try {
    var dots = document.querySelectorAll(".bio-dot");
    for (var di = 0; di < dots.length; di++) dots[di].addEventListener("click", function () { this.classList.add("hit"); renderBio(); });
    var btxt = document.getElementById("ks-bio-text");
    if (btxt) btxt.addEventListener("input", renderBio);
    var analyze = document.getElementById("ks-analyze");
    if (analyze) analyze.addEventListener("click", function () {
      var s = document.getElementById("ks-status"); if (s) s.textContent = "re-scoring your behavior\\u2026";
      renderBio(); send();
    });
    setInterval(renderBio, 600); // keep the live readout fresh as the visitor moves/types
  } catch (e) {}
  // Score after a short delay (a fast first verdict). In full mode, if the visitor hasn't produced enough
  // input yet the behavioral layer is omitted (no penalty) and we AUTO-RE-SCORE once they move/type enough,
  // so a real human gets a proper behavioral read without having to press Analyze.
  var ksFast = /(?:\\?|&)fast\\b/.test(location.search), ksRescored = false;
  function ksMaybeRescore() {
    if (ksRescored || (pts.length < 12 && keys.length < 4)) return;
    ksRescored = true;
    send();
  }
  setTimeout(function () {
    send();
    if (!ksFast) { addEventListener("mousemove", ksMaybeRescore); addEventListener("keydown", ksMaybeRescore); }
  }, ksFast ? 200 : 1200);
})();
</script></body></html>
"""
