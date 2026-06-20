// collector/livepage/main — browser entrypoint for the live detection page.
// Predicts the real browser, collects + enumerates this browser's fingerprint, evaluates rules
// per-browser (excluding ones that don't apply, lowering false positives), renders the verdict.

import { evaluate, type SignalMap, verdictFor } from "./engine.js";
import { coherence, notApplicable, predict } from "./predict.js";
import { armCollector } from "./probes.js";
import type { RegistryJSON } from "./registry.js";
import { render, type Surface } from "./render.js";

const COLLECT_DELAY_MS = 4000;

/** A stable FNV-1a hash of this browser's 2D canvas render — the per-surface identifier. */
function canvasHash(): string {
  try {
    const c = document.createElement("canvas");
    c.width = 200;
    c.height = 40;
    const ctx = c.getContext("2d");
    if (ctx === null) return "—";
    ctx.textBaseline = "top";
    ctx.font = "16px Arial";
    ctx.fillStyle = "#069";
    ctx.fillRect(0, 0, 200, 40);
    ctx.fillStyle = "#f60";
    ctx.fillText("Kitsune canvas ✨", 4, 4);
    const data = c.toDataURL();
    let h = 2166136261;
    for (let i = 0; i < data.length; i++) h = ((h ^ data.charCodeAt(i)) * 16777619) >>> 0;
    return (h >>> 0).toString(16);
  } catch {
    return "—";
  }
}

/** Group the fingerprint into per-surface cards (value + hash + tamper status from the fired tells). */
function surfaces(signals: SignalMap, fp: Record<string, string>): Surface[] {
  const on = (k: string): boolean => signals.get(`browser.${k}`) === true;
  const mk = (name: string, value: string, kinds: string[], hash?: string): Surface => {
    const tells = kinds.filter(on);
    const base: Surface = { name, value, tampered: tells.length > 0, tells };
    return hash !== undefined ? { ...base, hash } : base;
  };
  return [
    mk("Navigator", `${(fp["User-Agent"] ?? "").slice(0, 52)}…`, [
      "webdriver",
      "webdriver_spoofed",
      "webdriver_getter_tampered",
      "nav_property_spoofed",
      "automation_globals",
    ]),
    mk("WebGL", fp["WebGL renderer"] ?? "—", [
      "webgl_getparameter_tampered",
      "webgl_worker_divergence",
      "webgl_renderer_artifact",
    ]),
    mk(
      "Canvas",
      "2D render",
      ["canvas_lie", "canvas_noise", "canvas_worker_divergence"],
      canvasHash(),
    ),
    mk("Audio", "OfflineAudioContext", ["audio_noise", "audio_readback_noise"]),
    mk("Timezone", fp["Timezone"] ?? "—", [
      "timezone_inconsistent",
      "timezone_internal_incoherent",
      "timezone_worker_divergence",
    ]),
    mk("Functions", "native integrity", [
      "native_invariant_violated",
      "function_tostring_tampered",
      "tostring_tampered",
      "plugins_spoofed",
    ]),
    mk("Workers / realms", "main vs Worker/iframe", [
      "worker_divergence",
      "iframe_divergence",
      "worker_constructor_tampered",
      "worker_source_rewritten",
      "languages_worker_divergence",
    ]),
  ];
}

/** Read the raw, human-readable fingerprint surface (the enumerated values shown on the page). */
function rawFingerprint(): Record<string, string> {
  const nav = navigator as Navigator & { deviceMemory?: number };
  let renderer = "—";
  let vendor = "—";
  try {
    const gl = document.createElement("canvas").getContext("webgl");
    const dbg = gl && gl.getExtension("WEBGL_debug_renderer_info");
    if (gl && dbg) {
      renderer = String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL));
      vendor = String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL));
    }
  } catch {
    /* webgl unavailable */
  }
  let tz = "—";
  try {
    tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "—";
  } catch {
    /* intl unavailable */
  }
  return {
    "User-Agent": navigator.userAgent,
    "navigator.platform": navigator.platform || "—",
    "navigator.vendor": navigator.vendor || "—",
    Languages: (navigator.languages || []).join(", ") || "—",
    Timezone: tz,
    Screen: `${screen.width}×${screen.height} · DPR ${window.devicePixelRatio} · ${screen.colorDepth}-bit`,
    "Hardware concurrency": String(navigator.hardwareConcurrency ?? "—"),
    "Device memory": nav.deviceMemory != null ? `${nav.deviceMemory} GB` : "—",
    "Max touch points": String(navigator.maxTouchPoints ?? 0),
    "WebGL vendor": vendor,
    "WebGL renderer": renderer,
  };
}

async function main(): Promise<void> {
  const root = document.getElementById("app");
  if (root === null) return;

  // Arm behavioural listeners immediately so early mouse/key movement is captured while the page loads.
  const collector = armCollector();
  const registry = (await (await fetch("./rules.json")).json()) as RegistryJSON;

  // Give the visitor a moment to move the mouse / type so the behavioural layer has something to score.
  await new Promise((r) => setTimeout(r, COLLECT_DELAY_MS));

  const signals = await collector.collect();
  const prediction = predict();
  const clientRules = registry.rules.filter((r) => r.clientEvaluable);
  const fired = evaluate(clientRules, signals);

  // Per-browser gating: a fired detection that does not apply to the predicted browser/form-factor is
  // shown but excluded from the verdict — the mechanism that keeps real Firefox/Safari/mobile from being
  // mislabelled (e.g. navplatform_vs_ua on Android, where a Linux platform under an Android UA is normal).
  const naReasons = new Map<string, string>();
  const applicable = fired.filter((c) => {
    const reason = notApplicable(c.id, prediction);
    if (reason !== null) {
      naReasons.set(c.id, reason);
      return false;
    }
    return true;
  });

  const fingerprint = rawFingerprint();
  render(root, {
    prediction,
    coherence: coherence(prediction),
    fingerprint,
    surfaces: surfaces(signals, fingerprint),
    rules: registry.rules,
    fired: applicable,
    naReasons,
    verdict: verdictFor(applicable),
    rulesetVersion: registry.ruleset_version,
  });
}

void main();
