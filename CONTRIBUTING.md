# Contributing to Kitsune

Thanks for your interest. Kitsune is a polyglot monorepo; the golden rule is that **components
communicate only through the versioned contracts in `contracts/` — never by importing each other.**

## Conventions (enforced in CI)

- **2-line file header.** Every script's first two lines are comments: line 1 is
  `<component>/<module> — <what it is>`, line 2 is `<what it does>`. This lets tools (and agents) map
  the codebase by reading the first two lines. Checked by `scripts/check_headers.py`.
- **Conventional Commits.** e.g. `feat(detector): add JA4 coherence rule`, `fix(edge): …`,
  `docs:`, `test:`, `chore:`. Releases + the changelog are generated from these. The subject **must
  start lowercase** — commitlint rejects a leading uppercase word/acronym (`SEO`, `GeoLite2`, `N5`),
  so write `fix(geo): refresh GeoLite2 fallback`, not `fix(geo): GeoLite2 fallback`.
- **Single author.** Every commit must be authored *and* committed as
  `datascry <datascry@users.noreply.github.com>` — no other identity, and **no `Co-Authored-By`
  trailer** (in particular, omit the default Claude trailer). Set it once with
  `git config user.name datascry && git config user.email datascry@users.noreply.github.com`. The one
  sanctioned exception is the release-please bot's own `chore(main): release …` commit.
- **Strict typing everywhere.** Python `mypy --strict`; TypeScript `strict` + `noUncheckedIndexedAccess`
  + `exactOptionalPropertyTypes`; Go is statically typed and `go vet`-clean.
- **Tiered coverage.** Core logic (contracts, detector, harness, edge fingerprinting, collector
  logic) is gated at **≥95%**; inherently-IO components (browser/network/agent glue) carry
  integration tests at a lower gate. Don't chase the number with brittle mocks.

## Per-component workflow

| Component | Toolchain | Verify |
|---|---|---|
| `detector`, `harness` | uv + pytest + ruff + mypy | `uv run pytest && uv run ruff check . && uv run ruff format --check . && uv run mypy` |
| `edge` | Go (utls/uquic/quic-go) | `go test ./... -cover && go vet ./... && gofmt -l .` |
| `collector` | pnpm + vitest + tsc | `pnpm test && pnpm run typecheck && pnpm run lint && pnpm exec prettier --check .` |

Or run everything: `task ci` (the authoritative gate — it runs the headers check, every command
above, and the generated-docs `--check` pass). Install hooks once with `pre-commit install`.

## Pull requests

1. Branch from `main`; keep PRs focused.
2. Ensure `task ci` is green and coverage gates hold.
3. Add an ADR under `docs/adr/` for any significant design decision (see the template).
4. Update `CHANGELOG.md`'s _Unreleased_ section if your change is user-facing.

## Ethics (non-negotiable)

Evaders may target **only** Kitsune's own detector and the approved public test endpoints listed in
`harness/src/kitsune_harness/allowlist.py`. Never point an evader at a third-party or production
site. PRs that weaken the allow-list will be rejected.
