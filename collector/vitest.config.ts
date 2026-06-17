// collector/vitest.config — test + coverage configuration.
// Core logic gated at >=95%; the browser-glue entrypoint (index.ts) is excluded (tier-2 IO).

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/index.ts", "src/types.ts"],
      thresholds: { lines: 95, functions: 95, branches: 95, statements: 95 },
    },
  },
});
