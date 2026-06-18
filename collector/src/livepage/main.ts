// collector/livepage/main — browser entrypoint for the live detection page.
// Fetches the rule registry, collects this browser's signals, evaluates client-side, renders the verdict.

import { evaluate, verdictFor } from "./engine.js";
import { armCollector } from "./probes.js";
import type { RegistryJSON } from "./registry.js";
import { render } from "./render.js";

const COLLECT_DELAY_MS = 4000;

async function main(): Promise<void> {
  const root = document.getElementById("app");
  if (root === null) return;

  // Arm behavioural listeners immediately so early mouse/key movement is captured while the page loads.
  const collector = armCollector();

  const registry = (await (await fetch("./rules.json")).json()) as RegistryJSON;

  // Give the visitor a moment to move the mouse / type so the behavioural layer has something to score.
  await new Promise((r) => setTimeout(r, COLLECT_DELAY_MS));

  const signals = await collector.collect();
  const clientRules = registry.rules.filter((r) => r.clientEvaluable);
  const verdict = verdictFor(evaluate(clientRules, signals));
  render(root, registry.rules, verdict, registry.ruleset_version);
}

void main();
