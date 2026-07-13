// collector/livepage/render — paint the verdict, predicted browser, enumerated fingerprint, and the
// per-browser detection tables into the DOM. Pure DOM rendering; no network, no globals beyond root.

import type { Layer } from "../types.js";
import type { Contradiction, Verdict } from "./engine.js";
import type { Coherence, Prediction } from "./predict.js";
import type { RuleJSON } from "./registry.js";

const LAYER_ORDER: Layer[] = ["network", "browser", "behavioral", "reputation"];
// The coherence-spine order (mockup 1A): the two in-browser layers lead, the two edge-only layers follow.
const SPINE_ORDER: Layer[] = ["browser", "behavioral", "network", "reputation"];
// L1-redesign: verdict label -> its one semantic colour token (fox=bot, amber=suspicious, jade=human).
const VERDICT_VAR: Record<string, string> = {
  bot: "var(--fox)",
  suspicious: "var(--amber)",
  human: "var(--jade)",
};

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
  demo?: { label: string }; // L5: present when showing a spoofed-browser demo overlay (not the real verdict)
}

// L6: a one-line plain-language gloss per rule category (the "why it convicts" the title alone doesn't say).
const CATEGORY_WHY: Record<string, string> = {
  coherence: "cross-layer contradiction — values that cannot co-occur on one real browser",
  automation: "automation-framework surface (webdriver / CDP / injected globals)",
  artifact: "anti-detect implementation flaw (spoofing placeholder / tampered native)",
  environment: "a capability a real browser has is stripped/absent",
  behavioral: "human input biomechanics floor",
  reputation: "network reputation (datacenter / proxy exit)",
  prevalence: "a coherent but statistically improbable fingerprint",
};
const REGISTRY_URL = "https://github.com/datascry/kitsune/blob/main/contracts/rules/registry.yaml";

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
  // L6: link the rule id to its registry source (provenance) and gloss the category (the plain "why").
  const why = CATEGORY_WHY[rule.category] ?? "";
  const idLink = `<a class="rule-src" href="${REGISTRY_URL}" target="_blank" rel="noopener" title="view rule source in registry.yaml"><code>${esc(rule.id)}</code></a>`;
  return `<tr class="${cls}"><td class="mark">${mark}</td>
    <td>${idLink}${status}<div class="title">${esc(rule.title)}</div></td>
    <td title="${esc(why)}">${esc(rule.category)}</td><td class="weight">${rule.weight.toFixed(2)}</td></tr>`;
}

/** A derived one-line plain-language reason for the verdict (no reason is stored on the verdict itself). */
function verdictReason(verdict: Verdict, fired: Contradiction[]): string {
  const n = fired.length;
  const tell = n === 1 ? "tell" : "tells";
  if (verdict.label === "human")
    return "No convicting tell fired — this browser's features, navigator surface, Worker realm and behavioral biomechanics all describe one coherent, real browser.";
  if (verdict.label === "suspicious")
    return `${n} ${tell} fired — a coherent but statistically improbable fingerprint; not enough to convict on its own.`;
  return `${n} convicting ${tell} fired — values that cannot co-occur on one real browser. The instrumentation a spoofer needs is visible to the page.`;
}

/** The coherence spine (mockup 1A): per-layer dot + track + state. Browser/behavioral are judged in-browser;
 *  network/reputation are edge-only here (a browser cannot observe its own TLS/TCP/IP-reputation). */
function spineRows(verdict: Verdict): string {
  return SPINE_ORDER.map((l) => {
    const score = verdict.layers[l];
    const edgeOnly = l === "network" || l === "reputation";
    const dot = edgeOnly ? "var(--muted)" : score > 0 ? "var(--fox)" : "var(--jade)";
    const state = edgeOnly
      ? "edge only"
      : score > 0
        ? "flagged"
        : l === "behavioral"
          ? "human"
          : "clean";
    return `<div class="spine-row">
      <span class="spine-layer">${esc(l)}</span>
      <span class="spine-meter">
        <span class="spine-dot" style="background:${dot}"></span>
        <span class="spine-trk"><i style="width:${pct(score)};background:${dot}"></i></span>
        <span class="spine-state" style="color:${dot}">${esc(state)}</span>
      </span></div>`;
  }).join("");
}

/** The verdict hero: a giant label + score, a derived reason, three at-a-glance stats, and the coherence spine. */
function verdictHero(
  verdict: Verdict,
  coherence: Coherence,
  prediction: Prediction,
  fired: Contradiction[],
  rulesLen: number,
): string {
  const col = VERDICT_VAR[verdict.label] ?? "var(--ink)";
  const predEngOs = `${esc(prediction.engine)} · ${esc(prediction.os)}`;
  const claimEngOs = `${esc(coherence.claimedEngine)} · ${esc(coherence.claimedOs)}`;
  const border = coherence.match ? "var(--jade)" : "var(--fox)";
  const mtext = coherence.match ? "✓ coherent" : "✗ mismatch";
  return `<section class="vhero">
    <div class="vh-main" style="--vcol:${col}">
      <div class="eyebrow">Verdict · this browser</div>
      <div class="vh-big">
        <span class="vh-label display">${esc(verdict.label.toUpperCase())}</span>
        <span class="vh-score display">${pct(verdict.score)}</span>
      </div>
      <p class="vh-reason">${esc(verdictReason(verdict, fired))}</p>
      <div class="vh-stats">
        <span class="vstat"><span class="vk">bot-likelihood</span><span class="vv" style="color:${col}">${pct(verdict.score)}</span></span>
        <span class="vstat"><span class="vk">incoherence</span><span class="vv">${pct(verdict.incoherence)}</span></span>
        <span class="vstat"><span class="vk">detections fired</span><span class="vv">${fired.length} / ${rulesLen}</span></span>
      </div>
    </div>
    <div class="vh-spine">
      <div class="eyebrow">Coherence spine</div>
      ${spineRows(verdict)}
      <div class="coh-strip" style="border-color:${border}">
        <span class="coh-line"><span class="k">predicts</span> ${predEngOs} <span class="k">· ua claims</span> ${claimEngOs}</span>
        <span class="coh-verdict" style="color:${border}">${mtext}</span>
      </div>
      <p class="note coh-why">${esc(coherence.reason)} — a real browser's features and UA always agree; a spoofer's do not.</p>
    </div>
  </section>`;
}

/** The fired-detections list (mockup 1A) — only the convicting session tells, pulsing, id · title · category · weight. */
function firedList(fired: Contradiction[], edgeLen: number): string {
  const rows = fired
    .map((c) => {
      const why = CATEGORY_WHY[c.category] ?? "";
      const idLink = `<a class="rule-src" href="${REGISTRY_URL}" target="_blank" rel="noopener" title="view rule source in registry.yaml"><code>${esc(c.id)}</code></a>`;
      return `<div class="fdet-row">
        <span class="fdet-dot"></span>
        <div class="fdet-body">${idLink}<div class="fdet-title">${esc(c.title)}</div></div>
        <span class="fdet-cat" title="${esc(why)}">${esc(c.category)}</span>
        <span class="fdet-weight">${c.weight.toFixed(2)}</span>
      </div>`;
    })
    .join("");
  const body = fired.length
    ? rows
    : `<p class="note fdet-none">No convicting tell fired in your browser — nothing contradicts a coherent, real client.</p>`;
  return `<section class="fired-detections"><h2>Fired detections <span class="note">— what convicts this session</span></h2>
    <div class="fdet-list">${body}</div>
    <p class="note fdet-edge">+ ${edgeLen} edge detections (TLS · HTTP/2 · QUIC · TCP · IP-reputation) not evaluated in-browser.</p></section>`;
}

export function render(heroRoot: HTMLElement, detailRoot: HTMLElement, opts: RenderOpts): void {
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
    demo,
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
        <table class="detections"><thead><tr><th><span class="sr-only">status</span></th><th>detection</th><th>category</th><th>weight</th></tr></thead>
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

  // HERO ROOT (mockup 1A): the giant verdict + coherence spine, then the spoof-simulation bar. Re-rendered on
  // every demo overlay; the persistent behavioural panel and the JS click hooks (delegated on <main>) survive.
  heroRoot.innerHTML = `
    ${
      demo
        ? `<section class="demo-banner">▶ DEMO — showing how a <strong>${esc(demo.label)}</strong> would score, overlaid on your real signals. <button type="button" class="demo-reset">← back to my browser</button></section>`
        : ""
    }
    ${verdictHero(verdict, coherence, prediction, fired, rules.length)}
    <section class="spoofbar">
      <span class="sb-label">Simulate a spoof →</span>
      <button type="button" class="demo-spoof" data-preset="automation">Automation (webdriver)</button>
      <button type="button" class="demo-spoof" data-preset="canvas">Canvas spoof</button>
      <button type="button" class="demo-spoof" data-preset="worker">Worker divergence</button>
      <button type="button" class="share-btn" title="copy a text summary of this result">⧉ Copy result</button>
    </section>`;

  // DETAIL ROOT: the fired-detections spotlight, then the deep forensic reference (prediction, surfaces,
  // fingerprint, per-layer scores, full detection tables, not-applicable adjustments, and the edge-only list).
  detailRoot.innerHTML = `
    ${firedList(fired, edge.length)}
    ${predictionCard(prediction)}
    ${surfacesSection(surfaces)}
    ${fingerprintTable(fingerprint)}
    <section class="scores"><h2>Per-layer score</h2>${layerScoreHtml}
      <p class="note">Network &amp; reputation are 0 here by design: a browser cannot observe its own TLS/HTTP-2/QUIC/TCP
      fingerprint or its IP reputation — those need Kitsune's edge. ${client.length} of ${rules.length} detections ran in your browser,
      scored on a per-browser basis (${naRules.length} excluded as not-applicable). Ruleset ${esc(rulesetVersion)} · ${layerCount} coherence layers.</p>
    </section>
    <section class="results"><h2>Detections evaluated in your browser</h2>${byLayer}</section>
    ${naHtml}
    <section class="edge"><h2>Requires the Kitsune edge (${edge.length} not evaluated here)</h2>
      <p class="note">These read TLS/HTTP-2/QUIC/TCP or IP-reputation signals only the edge captures from the raw connection.</p>
      <ul class="edge-list">${edgeList}</ul>
    </section>`;
}
