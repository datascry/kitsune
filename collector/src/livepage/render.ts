// collector/livepage/render — paint the verdict, per-layer scores, and detection table into the DOM.
// Pure-ish DOM rendering for the live page; no network, no globals beyond the passed root (tier-2 IO).

import type { Layer } from "../types.js";
import type { Contradiction, Verdict } from "./engine.js";
import type { RuleJSON } from "./registry.js";

const LAYER_ORDER: Layer[] = ["network", "browser", "behavioral", "reputation"];

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

function ruleRow(rule: RuleJSON, fired: boolean, evidence: string[]): string {
  const cls = fired ? "fired" : "clear";
  const mark = fired ? "● FIRED" : "○ clear";
  const ev =
    fired && evidence.length ? `<div class="evidence">${esc(evidence.join(", "))}</div>` : "";
  const status = rule.status === "experimental" ? ' <span class="exp">exp</span>' : "";
  return `<tr class="${cls}">
    <td class="mark">${mark}</td>
    <td><code>${esc(rule.id)}</code>${status}<div class="title">${esc(rule.title)}</div>${ev}</td>
    <td>${esc(rule.category)}</td>
    <td class="weight">${rule.weight.toFixed(2)}</td>
  </tr>`;
}

/**
 * Render the full live result: verdict banner, per-layer score bars, the client-evaluated detection
 * table (fired first), and an honest "requires Kitsune edge" section for the rules a browser can't see.
 */
export function render(
  root: HTMLElement,
  rules: RuleJSON[],
  verdict: Verdict,
  rulesetVersion: string,
): void {
  const firedIds = new Map<string, Contradiction>(verdict.contradictions.map((c) => [c.id, c]));
  const client = rules.filter((r) => r.clientEvaluable);
  const edge = rules.filter((r) => !r.clientEvaluable);

  const layerScoreHtml = LAYER_ORDER.map((l) => scoreBar(l, verdict.layers[l])).join("");

  // Detection table per layer, fired rules first.
  const byLayer = LAYER_ORDER.filter((l) => client.some((r) => r.layers.includes(l)))
    .map((layer) => {
      const inLayer = client
        .filter((r) => r.layers.includes(layer))
        .sort(
          (a, b) => Number(firedIds.has(b.id)) - Number(firedIds.has(a.id)) || b.weight - a.weight,
        );
      const rows = inLayer
        .map((r) => ruleRow(r, firedIds.has(r.id), firedIds.get(r.id)?.evidence ?? []))
        .join("");
      return `<h3>${esc(layer)} <span class="count">${inLayer.filter((r) => firedIds.has(r.id)).length}/${inLayer.length} fired</span></h3>
        <table class="detections"><thead><tr><th></th><th>detection</th><th>category</th><th>weight</th></tr></thead>
        <tbody>${rows}</tbody></table>`;
    })
    .join("");

  const edgeList = edge
    .map(
      (r) =>
        `<li><code>${esc(r.id)}</code> — ${esc(r.title)} <span class="layers">[${esc(r.layers.join(", "))}]</span></li>`,
    )
    .join("");

  root.innerHTML = `
    <section class="verdict verdict-${verdict.label}">
      <div class="label">${esc(verdict.label.toUpperCase())}</div>
      <div class="score">bot-likelihood ${pct(verdict.score)}</div>
      <div class="sub">incoherence ${pct(verdict.incoherence)} · ruleset ${esc(rulesetVersion)}</div>
    </section>
    <section class="scores"><h2>Per-layer score</h2>${layerScoreHtml}
      <p class="note">Network &amp; reputation are 0 here by design: a browser cannot observe its own TLS/HTTP-2/QUIC/TCP
      fingerprint or its IP reputation — those need Kitsune's edge. ${client.length} of ${rules.length} detections ran in your browser.</p>
    </section>
    <section class="results"><h2>Detections evaluated in your browser</h2>${byLayer}</section>
    <section class="edge"><h2>Requires the Kitsune edge (${edge.length} not evaluated here)</h2>
      <p class="note">These read TLS/HTTP-2/QUIC/TCP or IP-reputation signals only the edge captures from the raw connection.</p>
      <ul class="edge-list">${edgeList}</ul>
    </section>`;
}
