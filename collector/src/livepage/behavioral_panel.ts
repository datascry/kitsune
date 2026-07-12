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
  const verdict = !r.ready ? "gathering…" : r.fires ? "bot-like" : "human-like";
  const shown = r.ready ? r.value.toFixed(3) : "—";
  return `<div class="bp-row ${cls}">
    <div class="bp-row-l"><div class="bp-label">${esc(r.label)}</div><code class="bp-rid">${esc(r.ruleId)}</code></div>
    <div class="bp-row-r"><span class="bp-value">${shown}</span>
      <div class="bp-floor">floor ${esc(r.floorText)} · ${verdict}</div></div>
  </div>`;
}

/** The live, repainting region: a mode note (live vs frozen bot demo), the biomech rows, and a one-line summary. */
function metricsHtml(rows: BehavioralRow[], note: string): string {
  const fired = rows.filter((r) => r.fires).length;
  return `<p class="note bp-mode">${esc(note)}</p>
    <div class="bp-rows">${rows.map(rowHtml).join("")}</div>
    <p class="bp-summary">${fired}/${rows.length} biomech floors currently tripped.</p>`;
}

/** The masthead counts line (updated each draw without rebuilding the controls, so the text input keeps focus). */
function countsText(snapshot: BehavioralSnapshot): string {
  const motion = snapshot.enoughMotion
    ? "motion floor met"
    : `need ${BEHAVIOR_MIN_POINTERS}+ to judge mouse`;
  const keyState = snapshot.enoughKeys
    ? "keys floor met"
    : `type ${BEHAVIOR_MIN_KEYS}+ keys to judge cadence`;
  return `${snapshot.pointerSamples} pointer samples · ${snapshot.keystrokes} keystrokes — ${motion} · ${keyState}`;
}

/** The interactive controls — buttons (elicit pointer travel) + a text input (keystroke timing). Built ONCE
 * and never repainted, so typing keeps focus while the metrics slot refreshes underneath. Touch-aware copy
 * (the biomech floors are mouse-calibrated, so on a touch device they read as advisory, not convicting). */
function controlsHtml(isTouch: boolean, hasReeval: boolean): string {
  const placeholder = "Type a sentence to measure keystroke cadence…";
  const targets = isTouch ? "Tap and swipe across the targets" : "Click the targets";
  return `<input type="text" class="bp-text" autocomplete="off" autocapitalize="off" spellcheck="false"
      aria-label="type to measure keystroke timing" placeholder="${placeholder}" />
    <p class="note bp-pad-help">${targets} to feed real pointer travel:</p>
    <div class="bp-pad">${[1, 2, 3, 4, 5]
      .map((n) => `<button type="button" class="bp-dot" data-n="${n}">${n}</button>`)
      .join("")}</div>
    <div class="bp-actions">
      <button type="button" class="bp-demo">Demo a synthetic bot path ↻</button>
      ${hasReeval ? '<button type="button" class="bp-reeval">Re-evaluate my detections ↻</button>' : ""}
    </div>`;
}

/**
 * Mount the interactive behavioural panel into `container`. Renders a persistent control shell (clickable
 * buttons + a text input that drive real mouse dynamics + keystroke timing into the collector) plus a live
 * metrics slot that polls the collector as the visitor moves/types, and a button that runs the SAME metric
 * code over a scripted bot path so the floors visibly fire — making the behavioural layer tangible.
 *
 * The control shell is built once; only the `.bp-live` slot (and the header counts) repaint, so the text
 * input keeps focus/value across refreshes.
 */
export function mountBehavioralPanel(
  container: HTMLElement,
  collector: { snapshotBehavioral(): BehavioralSnapshot },
  rules: RuleJSON[],
  opts: { isTouch?: boolean; onReevaluate?: () => void } = {},
): void {
  const isTouch = opts.isTouch === true;
  const liveNote = isTouch
    ? "Touch/pointer dynamics measured live. The biomech floors are mouse-calibrated, so they read as advisory on a touch device."
    : "Real human motion stays clear of every floor; a scripted path does not.";
  const demoNote =
    "Scripted constant-velocity straight path — every biomech floor trips. Move your mouse to return to live mode.";
  let demoing = false;

  container.innerHTML = `<div class="bp-head">
      <h2 class="bp-h">Behavioral layer &mdash; live</h2>
      <span class="bp-counts note"></span>
    </div>
    <p class="note bp-lede">Interact below — the biomechanics are measured in your browser against the same
      registry floors the detector uses.</p>
    <div class="bp-grid">
      <div class="bp-controls">${controlsHtml(isTouch, opts.onReevaluate !== undefined)}</div>
      <div class="bp-live"></div>
    </div>`;
  const live = container.querySelector(".bp-live") as HTMLElement;
  const counts = container.querySelector(".bp-counts") as HTMLElement;

  const draw = (snapshot: BehavioralSnapshot, note: string): void => {
    counts.textContent = countsText(snapshot);
    live.innerHTML = metricsHtml(evaluateBehavioral(snapshot, rules), note);
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
