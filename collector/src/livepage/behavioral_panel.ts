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

/** The live, repainting region: status line + metrics table + summary. */
function metricsHtml(snapshot: BehavioralSnapshot, rows: BehavioralRow[], note: string): string {
  const fired = rows.filter((r) => r.fires).length;
  const ptr = `${snapshot.pointerSamples} pointer samples`;
  const motion = snapshot.enoughMotion
    ? '<span class="ok">motion floor met</span>'
    : `<span class="wait">need ${BEHAVIOR_MIN_POINTERS}+ to judge mouse</span>`;
  const keyState = snapshot.enoughKeys
    ? '<span class="ok">keys floor met</span>'
    : `<span class="wait">type ${BEHAVIOR_MIN_KEYS}+ keys to judge cadence</span>`;
  return `<p class="bp-status">${esc(ptr)} · ${snapshot.keystrokes} keystrokes — ${motion} · ${keyState}</p>
    <p class="note">${esc(note)}</p>
    <table class="bp-table"><thead><tr><th>metric</th><th>measured</th><th>bot floor</th><th>verdict</th></tr></thead>
      <tbody>${rows.map(rowHtml).join("")}</tbody></table>
    <p class="bp-summary">${fired}/${rows.length} biomech floors currently tripped.</p>`;
}

/** The interactive controls — buttons (elicit pointer travel) + a text input (keystroke timing). Built ONCE
 * and never repainted, so typing keeps focus while the metrics slot refreshes underneath. Touch-aware copy
 * (the biomech floors are mouse-calibrated, so on a touch device they read as advisory, not convicting). */
function controlsHtml(isTouch: boolean): string {
  const help = isTouch
    ? `Tap the buttons and swipe across them, then type a sentence — your touch/pointer dynamics and
       keystroke timing are measured live. <em>Note: the biomech floors are mouse-calibrated, so they are
       advisory on a touch device.</em>`
    : `Move your mouse to the buttons and click them, then type a sentence — your mouse dynamics and
       keystroke timing are measured live against the registry floors.`;
  const placeholder = "Type a sentence here to measure keystroke timing…";
  return `<p class="note bp-help">${help}</p>
    <div class="bp-pad">${[1, 2, 3, 4, 5]
      .map((n) => `<button type="button" class="bp-dot" data-n="${n}">${n}</button>`)
      .join("")}</div>
    <input type="text" class="bp-text" autocomplete="off" autocapitalize="off" spellcheck="false"
      aria-label="type to measure keystroke timing" placeholder="${placeholder}" />`;
}

/**
 * Mount the interactive behavioural panel into `container`. Renders a persistent control shell (clickable
 * buttons + a text input that drive real mouse dynamics + keystroke timing into the collector) plus a live
 * metrics slot that polls the collector as the visitor moves/types, and a button that runs the SAME metric
 * code over a scripted bot path so the floors visibly fire — making the behavioural layer tangible.
 *
 * The control shell is built once; only the `.bp-live` slot repaints, so the text input keeps focus/value
 * across refreshes.
 */
export function mountBehavioralPanel(
  container: HTMLElement,
  collector: { snapshotBehavioral(): BehavioralSnapshot },
  rules: RuleJSON[],
  opts: { isTouch?: boolean; onReevaluate?: () => void } = {},
): void {
  const liveNote = "Real human motion stays clear of every floor; a scripted path does not.";
  const demoNote =
    "Scripted constant-velocity straight path — every biomech floor trips. Move your mouse to return to live mode.";
  let demoing = false;

  container.innerHTML = `<h2>Behavioral layer — live biomechanics
      <span class="note">— measured in your browser against the same registry floors the detector uses</span></h2>
    ${controlsHtml(opts.isTouch === true)}
    <div class="bp-live"></div>
    <div class="bp-actions">
      <button type="button" class="bp-demo">Demo a synthetic bot path ↻</button>
      ${opts.onReevaluate ? '<button type="button" class="bp-reeval">Re-evaluate my detections ↻</button>' : ""}
    </div>`;
  const live = container.querySelector(".bp-live") as HTMLElement;

  const draw = (snapshot: BehavioralSnapshot, note: string): void => {
    live.innerHTML = metricsHtml(snapshot, evaluateBehavioral(snapshot, rules), note);
  };

  draw(collector.snapshotBehavioral(), liveNote);

  // Clicking a target marks it hit (cosmetic) — the value is the mouse travel + click it elicits.
  // The demo button freezes the live slot on a synthetic bot path. Event-delegated on the stable container.
  container.addEventListener("click", (e) => {
    const t = e.target as HTMLElement | null;
    if (t?.classList.contains("bp-dot")) {
      t.classList.add("hit");
      return;
    }
    if (t?.classList.contains("bp-demo")) {
      demoing = true;
      draw(syntheticBotSnapshot(), demoNote);
      return;
    }
    // L2: re-score the verdict against the visitor's now-richer interaction (collect() re-snapshots).
    if (t?.classList.contains("bp-reeval") && opts.onReevaluate) opts.onReevaluate();
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
