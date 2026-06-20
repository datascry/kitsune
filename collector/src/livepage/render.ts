// collector/livepage/render — paint the verdict, predicted browser, enumerated fingerprint, and the
// per-browser detection tables into the DOM. Pure DOM rendering; no network, no globals beyond root.

import type { Layer } from "../types.js";
import type { Contradiction, Verdict } from "./engine.js";
import type { Coherence, Prediction } from "./predict.js";
import type { RuleJSON } from "./registry.js";

const LAYER_ORDER: Layer[] = ["network", "browser", "behavioral", "reputation"];

/** One fingerprint surface: its value/hash and whether any tamper tell fired against it. */
export interface Surface {
  name: string;
  value: string;
  hash?: string;
  tampered: boolean;
  tells: string[];
}

export interface RenderOpts {
  prediction: Prediction;
  coherence: Coherence;
  fingerprint: Record<string, string>;
  surfaces: Surface[];
  rules: RuleJSON[];
  fired: Contradiction[]; // applicable fired detections (counted toward the verdict)
  naReasons: Map<string, string>; // ruleId -> why it fired but does NOT apply to this browser
  verdict: Verdict; // computed over the applicable detections only
  rulesetVersion: string;
}

function esc(s: string): string {
  return s.replace(
    /[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c] ?? c,
  );
}

function pct(x: number): string {
  return `${Math.round(x * 100)}%`;
}

function scoreBar(label: string, value: number): string {
  return `<div class="bar"><span class="bar-label">${esc(label)}</span>
    <span class="bar-track"><span class="bar-fill" style="width:${pct(value)}"></span></span>
    <span class="bar-val">${pct(value)}</span></div>`;
}

function predictionCard(p: Prediction): string {
  const items: [string, string][] = [
    ["Browser", p.browser],
    ["Engine", p.engine],
    ["OS", p.os],
    ["Form factor", p.formFactor],
    ["Confidence", pct(p.confidence)],
  ];
  const rows = items
    .map(
      ([k, v]) =>
        `<div class="kv"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`,
    )
    .join("");
  const ev = p.evidence.map((e) => `<li>${esc(e)}</li>`).join("");
  return `<section class="predict">
    <h2>Predicted browser <span class="note">— from feature detection, independent of the User-Agent</span></h2>
    <div class="predict-grid">${rows}</div>
    <details class="ev"><summary>why (${p.evidence.length} feature checks)</summary><ul>${ev}</ul></details>
  </section>`;
}

function fingerprintTable(fp: Record<string, string>): string {
  const rows = Object.entries(fp)
    .map(
      ([k, v]) =>
        `<tr><td class="fk">${esc(k)}</td><td class="fv"><code>${esc(v)}</code></td></tr>`,
    )
    .join("");
  return `<section class="fingerprint"><h2>Enumerated values <span class="note">— the raw fingerprint surface</span></h2>
    <table class="fp-table"><tbody>${rows}</tbody></table></section>`;
}

function coherenceBanner(c: Coherence, p: Prediction): string {
  const cls = c.match ? "match" : "mismatch";
  const verdict = c.match ? "✓ coherent" : "✗ mismatch";
  return `<section class="coherence ${cls}">
    <div class="side"><span class="cap">Feature prediction</span><span class="val">${esc(p.engine)} · ${esc(p.os)}</span></div>
    <div class="verdict-cell">${verdict}</div>
    <div class="side"><span class="cap">Claimed (User-Agent)</span><span class="val">${esc(c.claimedEngine)} · ${esc(c.claimedOs)}</span></div>
  </section>
  <p class="note">${esc(c.reason)} — a real browser's features and UA always agree; a spoofer's do not.</p>`;
}

function surfacesSection(surfaces: Surface[]): string {
  const cards = surfaces
    .map((s) => {
      const chip = s.tampered ? "tampered" : "clean";
      const hash = s.hash ? `<div class="shash">hash ${esc(s.hash)}</div>` : "";
      const tells = s.tampered ? `<div class="stells">${s.tells.map(esc).join(", ")}</div>` : "";
      return `<div class="surface ${s.tampered ? "tampered" : ""}">
        <div class="top"><span class="sname">${esc(s.name)}</span><span class="chip">${chip}</span></div>
        <div class="sval">${esc(s.value)}</div>${hash}${tells}</div>`;
    })
    .join("");
  const dirty = surfaces.filter((s) => s.tampered).length;
  return `<section><h2>Fingerprint surfaces <span class="note">— value · hash · tamper status (${dirty} tampered)</span></h2>
    <div class="surfaces">${cards}</div></section>`;
}

function ruleRow(rule: RuleJSON, fired: boolean): string {
  const cls = fired ? "fired" : "clear";
  const mark = fired ? "● FIRED" : "○ clear";
  const status = rule.status === "experimental" ? ' <span class="exp">exp</span>' : "";
  return `<tr class="${cls}"><td class="mark">${mark}</td>
    <td><code>${esc(rule.id)}</code>${status}<div class="title">${esc(rule.title)}</div></td>
    <td>${esc(rule.category)}</td><td class="weight">${rule.weight.toFixed(2)}</td></tr>`;
}

export function render(root: HTMLElement, opts: RenderOpts): void {
  const {
    prediction,
    coherence,
    fingerprint,
    surfaces,
    rules,
    fired,
    naReasons,
    verdict,
    rulesetVersion,
  } = opts;
  const firedIds = new Set(fired.map((c) => c.id));
  const client = rules.filter((r) => r.clientEvaluable);
  const edge = rules.filter((r) => !r.clientEvaluable);
  const naRules = client.filter((r) => naReasons.has(r.id));
  const layerCount = new Set(rules.flatMap((r) => r.layers)).size;

  const layerScoreHtml = LAYER_ORDER.map((l) => scoreBar(l, verdict.layers[l])).join("");

  // Per-layer detection table: only the APPLICABLE rules, fired first. N/A rules move to their own section.
  const byLayer = LAYER_ORDER.filter((l) =>
    client.some((r) => r.layers.includes(l) && !naReasons.has(r.id)),
  )
    .map((layer) => {
      const inLayer = client
        .filter((r) => r.layers.includes(layer) && !naReasons.has(r.id))
        .sort(
          (a, b) => Number(firedIds.has(b.id)) - Number(firedIds.has(a.id)) || b.weight - a.weight,
        );
      const rows = inLayer.map((r) => ruleRow(r, firedIds.has(r.id))).join("");
      const n = inLayer.filter((r) => firedIds.has(r.id)).length;
      return `<h3>${esc(layer)} <span class="count">${n}/${inLayer.length} fired</span></h3>
        <table class="detections"><thead><tr><th></th><th>detection</th><th>category</th><th>weight</th></tr></thead>
        <tbody>${rows}</tbody></table>`;
    })
    .join("");

  const naHtml = naRules.length
    ? `<section class="na"><h2>Adjusted for your browser
        <span class="note">— fired, but expected for ${esc(prediction.browser)}/${esc(prediction.formFactor)}; excluded from the verdict</span></h2>
      <ul class="na-list">${naRules
        .map((r) => `<li><code>${esc(r.id)}</code> — ${esc(naReasons.get(r.id) ?? "")}</li>`)
        .join("")}</ul></section>`
    : "";

  const edgeList = edge
    .map(
      (r) =>
        `<li><code>${esc(r.id)}</code> — ${esc(r.title)} <span class="layers">[${esc(r.layers.join(", "))}]</span></li>`,
    )
    .join("");

  root.innerHTML = `
    <section class="hero">
      <div class="hero-stat"><strong>${rules.length}</strong><span>detection rules</span></div>
      <div class="hero-stat"><strong>${layerCount}</strong><span>coherence layers</span></div>
      <div class="hero-stat"><strong>${client.length}</strong><span>ran in your browser</span></div>
      <div class="hero-stat"><strong>${edge.length}</strong><span>need the edge</span></div>
      <p class="hero-note">Every rule is cross-layer coherence-as-data — the same registry the server-side
        detector evaluates, ruleset ${esc(rulesetVersion)}.</p>
    </section>
    <section class="verdict verdict-${verdict.label}">
      <div class="label">${esc(verdict.label.toUpperCase())}</div>
      <div class="score">bot-likelihood ${pct(verdict.score)}</div>
      <div class="sub">incoherence ${pct(verdict.incoherence)} · ruleset ${esc(rulesetVersion)}</div>
    </section>
    ${coherenceBanner(coherence, prediction)}
    ${predictionCard(prediction)}
    ${surfacesSection(surfaces)}
    ${fingerprintTable(fingerprint)}
    <section class="scores"><h2>Per-layer score</h2>${layerScoreHtml}
      <p class="note">Network &amp; reputation are 0 here by design: a browser cannot observe its own TLS/HTTP-2/QUIC/TCP
      fingerprint or its IP reputation — those need Kitsune's edge. ${client.length} of ${rules.length} detections ran in your browser,
      scored on a per-browser basis (${naRules.length} excluded as not-applicable).</p>
    </section>
    <section class="results"><h2>Detections evaluated in your browser</h2>${byLayer}</section>
    <section class="behavioral-panel" id="behavioral-panel"></section>
    ${naHtml}
    <section class="edge"><h2>Requires the Kitsune edge (${edge.length} not evaluated here)</h2>
      <p class="note">These read TLS/HTTP-2/QUIC/TCP or IP-reputation signals only the edge captures from the raw connection.</p>
      <ul class="edge-list">${edgeList}</ul>
    </section>`;
}
