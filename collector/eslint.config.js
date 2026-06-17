// collector/eslint.config — flat ESLint config using typescript-eslint recommended rules.
// Lints src + tests; ignores build and coverage output.

import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/", "coverage/"] },
  ...tseslint.configs.recommended,
);
