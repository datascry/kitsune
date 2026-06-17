# CLAUDE.md — guidance for AI agents working in this repo

Kitsune is a **bot detection ⇄ evasion lab**: a blue-team `detector` and a red-team evader fleet,
run against each other to produce a per-layer scoreboard. Core thesis: **flag incoherence across
layers, not just bad signals.** Start with [`docs/architecture.md`](docs/architecture.md).

## ⛔ Hard rules (non-negotiable)

### Git identity — only ever this author/email

- **Always commit and author as:** `datascry <datascry@users.noreply.github.com>`.
- **NEVER commit any other email** — not as author, not as committer, not in a `Co-Authored-By`
  trailer, not in PR descriptions or metadata, anywhere. This explicitly means **do not add the
  default `Co-Authored-By: Claude … <…@anthropic.com>` trailer** — omit it entirely.
- Set it before committing: `git config user.name datascry && git config user.email datascry@users.noreply.github.com`.

### Ethics — enforced in code

Evaders may target **only** Kitsune's own detector and the approved public test endpoints in
`harness/src/kitsune_harness/allowlist.py`. Never a third-party/production site. Don't weaken the
allow-list.

## Conventions (CI-enforced)

- **2-line file header** on every script: line 1 `<component>/<module> — <what it is>`, line 2
  `<what it does>`. So agents can map the codebase by reading the first two lines. Checked by
  `scripts/check_headers.py`.
- **Conventional Commits** (`feat(detector): …`, `fix(edge): …`, `docs:`, `test:`, `chore:`); scopes:
  contracts, detector, harness, edge, collector, evaders, docs, ci, repo. Releases/changelog are
  generated from these.
- **Strict typing everywhere:** Python `mypy --strict`; TS `strict` + `noUncheckedIndexedAccess` +
  `exactOptionalPropertyTypes`; Go `go vet`-clean.
- **Tiered coverage:** core logic ≥95% (currently 100%); IO/integration components lower + e2e.
  Don't chase the number with brittle mocks.
- **Contracts are the only coupling.** Components communicate via the JSON Schemas in `contracts/`
  over HTTP and **never import each other**.

## Layout

| Dir | Lang | Role |
|---|---|---|
| `contracts/` | JSON Schema | Stable wire contracts + coherence-rule registry (the core). |
| `detector/` | Python | Session correlation, coherence engine, scoring, store, `/ingest`. |
| `harness/` | Python | Scenario runner + reproducible scoreboard; ethics allow-list. |
| `edge/` | Go | Raw ClientHello → JA3/JA4, session minting, signal forwarding. |
| `collector/` | TypeScript | In-browser fingerprint + behavioral signal collection. |
| `evaders/` | Py/TS/Go | Red-team ladder (stubs: vanilla, stealth, agent, go-tls). |
| `docs/adr/` | — | MADR architecture decision records. |

## Verify before committing

```sh
task ci          # headers · detector · harness · edge · collector
# or per component:
cd detector && uv run ruff check . && uv run mypy && uv run pytest
cd edge && go vet ./... && go test ./... -cover     # needs Go (or docker golang:1.23-alpine)
cd collector && pnpm run typecheck && pnpm run lint && pnpm test
```

Go and Node are not installed in some environments — use Docker (`golang:1.23-alpine`,
`node:22-alpine`) to build/test those components.
