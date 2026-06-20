// collector/livepage/behavioral_panel — live, interactive behavioural-layer panel (DOM glue).
// Polls the collector to paint measured biomechanics vs the registry floors; wires the "demo a bot path" button.

import {
  type BehavioralRow,
  evaluateBehavioral,
  syntheticBotSnapshot,
} from "./behavioral_metrics.js";
import { BEHAVIOR_MIN_KEYS, BEHAVIOR_MIN_POINTERS, type BehavioralSnapshot } from "./probes.js";
import type { RuleJSON } from "./registry.js";

function esc(s: string): string {
  return s.replace(
    /[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c] ?? c,
  );
}

function rowHtml(r: BehavioralRow): string {
  const cls = !r.ready ? "pending" : r.fires ? "bot" : "human";
  const verdict = !r.ready ? "gathering…" : r.fires ? "● bot-like" : "○ human-like";
  const shown = r.ready ? r.value.toFixed(3) : "—";
  return `<tr class="${cls}">
    <td><code>${esc(r.ruleId)}</code><div class="bp-title">${esc(r.label)}</div></td>
    <td class="bp-val">${shown}</td>
    <td class="bp-floor">${esc(r.floorText)}</td>
    <td class="bp-verdict">${verdict}</td></tr>`;
}

function panelHtml(snapshot: BehavioralSnapshot, rows: BehavioralRow[], note: string): string {
  const fired = rows.filter((r) => r.fires).length;
  const ptr = `${snapshot.pointerSamples} pointer samples`;
  const motion = snapshot.enoughMotion
    ? '<span class="ok">motion floor met</span>'
    : `<span class="wait">need ${BEHAVIOR_MIN_POINTERS}+ to judge mouse</span>`;
  const keyState = snapshot.enoughKeys
    ? '<span class="ok">keys floor met</span>'
    : `<span class="wait">type ${BEHAVIOR_MIN_KEYS}+ keys to judge cadence</span>`;
  return `<h2>Behavioral layer — live biomechanics
      <span class="note">— measured in your browser against the same registry floors the detector uses</span></h2>
    <p class="bp-status">${esc(ptr)} · ${snapshot.keystrokes} keystrokes — ${motion} · ${keyState}</p>
    <p class="note">${esc(note)}</p>
    <table class="bp-table"><thead><tr><th>metric</th><th>measured</th><th>bot floor</th><th>verdict</th></tr></thead>
      <tbody>${rows.map(rowHtml).join("")}</tbody></table>
    <p class="bp-summary">${fired}/${rows.length} biomech floors currently tripped.</p>
    <button type="button" class="bp-demo">Demo a synthetic bot path ↻</button>`;
}

/**
 * Mount the interactive behavioural panel into `container`. Polls the live collector so the metrics update
 * as the visitor moves/types, and wires a button that runs the SAME metric code over a scripted bot path so
 * the floors visibly fire — making the behavioural layer tangible even when a human trips nothing.
 */
export function mountBehavioralPanel(
  container: HTMLElement,
  collector: { snapshotBehavioral(): BehavioralSnapshot },
  rules: RuleJSON[],
): void {
  const liveNote =
    "Move the mouse and type below — real human motion stays clear of every floor; a scripted path does not.";
  const demoNote =
    "Scripted constant-velocity straight path — every biomech floor trips. Move your mouse to return to live mode.";
  let demoing = false;

  const draw = (snapshot: BehavioralSnapshot, note: string): void => {
    container.innerHTML = panelHtml(snapshot, evaluateBehavioral(snapshot, rules), note);
  };

  draw(collector.snapshotBehavioral(), liveNote);

  // Demo button (event-delegated, so it survives every repaint): freeze the panel on a synthetic bot path.
  container.addEventListener("click", (e) => {
    if (!(e.target as HTMLElement | null)?.classList.contains("bp-demo")) return;
    demoing = true;
    draw(syntheticBotSnapshot(), demoNote);
  });
  // Any genuine pointer motion exits the frozen demo back to live readings.
  window.addEventListener("mousemove", () => {
    demoing = false;
  });
  // Live refresh: re-read the collector on a cheap interval (skipped while the bot demo is frozen).
  setInterval(() => {
    if (!demoing) draw(collector.snapshotBehavioral(), liveNote);
  }, 700);
}
