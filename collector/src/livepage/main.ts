// collector/livepage/main — browser entrypoint for the live detection page.
// Predicts the real browser, collects + enumerates this browser's fingerprint, evaluates rules
// per-browser (excluding ones that don't apply, lowering false positives), renders the verdict.

import { evaluate, verdictFor } from "./engine.js";
import { notApplicable, predict } from "./predict.js";
import { armCollector } from "./probes.js";
import type { RegistryJSON } from "./registry.js";
import { render } from "./render.js";

const COLLECT_DELAY_MS = 4000;

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

  render(root, {
    prediction,
    fingerprint: rawFingerprint(),
    rules: registry.rules,
    fired: applicable,
    naReasons,
    verdict: verdictFor(applicable),
    rulesetVersion: registry.ruleset_version,
  });
}

void main();
