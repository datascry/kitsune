// commitlint.config — enforce Conventional Commits in CI.
// Scopes map to the repo's components so history reads cleanly and release-please can version it.

export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "scope-enum": [
      1,
      "always",
      ["contracts", "detector", "harness", "edge", "collector", "evaders", "arena", "fleet", "docs", "ci", "repo"],
    ],
  },
};
