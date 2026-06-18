// collector/vitest.config — test + coverage configuration.
// Core logic gated at >=95%; the browser-glue entrypoint (index.ts) is excluded (tier-2 IO).

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: [
        "src/index.ts",
        "src/types.ts",
        "src/livepage/registry.ts", // types-only — no runtime code to cover

        // Live-page browser glue (DOM/navigator IO, like index.ts) — verified via the build + e2e, not unit.
        "src/livepage/probes.ts",
        "src/livepage/render.ts",
        "src/livepage/main.ts",
      ],
      thresholds: { lines: 95, functions: 95, branches: 95, statements: 95 },
    },
  },
});
