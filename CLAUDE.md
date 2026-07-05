# CLAUDE.md — guidance for AI agents working in this repo

Kitsune is a **bot detection ⇄ evasion lab**: a blue-team `detector` and a red-team evader fleet, run
against each other to produce a per-layer scoreboard. Core thesis: **flag incoherence across layers,
not just bad signals.**

**Orient:** [`docs/architecture.md`](docs/architecture.md) for the design; [`docs/frontier.md`](docs/frontier.md)
for where the arms race stands *right now* — the living state doc (saturated / open / external-bound),
reconciled on every axis close.

## ⛔ Hard rules (non-negotiable)

### Git identity — only ever `datascry`

- **Commit and author as `datascry <datascry@users.noreply.github.com>`, always.** Set it before
  committing: `git config user.name datascry && git config user.email datascry@users.noreply.github.com`.
- **NEVER any other email** — not as author, not as committer, not in a `Co-Authored-By` trailer, not in
  a PR description or metadata, anywhere. This explicitly means **omit the default
  `Co-Authored-By: Claude … <…@anthropic.com>` trailer** entirely.
- **Merge your own PRs with `gh pr merge --rebase`** — it preserves the datascry committer. `--squash`
  stamps the merge commit's committer as `GitHub <noreply@github.com>`, a foreign identity that violates
  this rule.
- **One accepted exception:** release-please's own `chore(main): release …` commit is authored by
  `github-actions[bot]`; merging that release PR (as datascry) is the sanctioned release path. That single
  bot-authored commit only — **every** other commit (features, fixes, docs, tests, applying a
  dependency/bot PR locally) stays datascry-authored, and you never set a non-datascry author/committer on
  a commit you make yourself.

### Ethics — enforced in code

Evaders, arena, and fleet may target **only** Kitsune's own detector/edge/arena and the approved endpoints
in `harness/src/kitsune_harness/allowlist.py`. Never a third-party/production site. **Never weaken the
allow-list.**

## Layout

| Dir | Lang | Role |
|---|---|---|
| `contracts/` | JSON Schema | Stable wire contracts + coherence-rule registry (the core). |
| `detector/` | Python | Session correlation, coherence engine, scoring, store, `/ingest`. |
| `harness/` | Python | Scenario runner + reproducible scoreboard; ethics allow-list. |
| `edge/` | Go | Raw ClientHello → JA3/JA4, HTTP/2 + QUIC/HTTP-3 + TCP/IP fingerprints, session minting, signal forwarding. |
| `collector/` | TypeScript | In-browser signal collection — a **focused production** page script (`src/index.ts`→`collect.ts`) + a **full self-test** page (`src/livepage/`). NB: the detector serves its OWN full inline collector (`detector/…/demo.py`), the authoritative full suite rules are validated against. Three collectors, distinct jobs — see [`docs/architecture.md`](docs/architecture.md) §3. |
| `evaders/` | Py/TS/Go | Red-team ladder of real anti-detect tools/browsers — CDP (`nodriver`, `zendriver`, `pydoll`, `selenium-driverless`, `stealth`, `undetected`), engine-level (`camoufox`, `brave`), TLS/kernel forgers (`os-spoof`, `go-tls`, `azuretls`, `curl-impersonate`, `primp`, `chain-mitm`), the LLM `agent`, arena solvers, DoS testbeds, … — see [`evaders/README.md`](evaders/README.md) for the full ladder. |
| `fleet/` | Python | **Skulk** — fleet adversary-emulation kit (cloned / randomizer / trace-replay / fuzzy strategies) for testing coordination defenses. Authorization-scoped in code (`scope.py`); emits coordination-shaped sessions to a detector's `/ingest`, NOT a flood/DoS/credential tool. See [`fleet/README.md`](fleet/README.md). |
| `arena/` | Go | Public self-hosted **challenge gates** (PoW · CAPTCHA text/math/honeypot · slider · rotate · emoji/Quick-Draw/procedural-shape image-select · reCAPTCHA-style checkbox · managed ladder · PACT · rate-limit · virtual queue · **`track` real-time visual-tracking that convicts LLM browser agents via `bh.arena_stale_snapshot`**), each easy/medium/hard where it has a difficulty axis. Owned infra only; the detector relays `/arena/*` and joins the gate verdict to its coherence verdict — see [`docs/arena.md`](docs/arena.md). |
| `docs/adr/` | — | MADR architecture decision records. |

## Conventions (CI-enforced)

- **2-line header on every script:** line 1 `<component>/<module> — <what it is>`, line 2 `<what it does>` —
  so an agent can map the codebase from the first two lines. Checked by `scripts/check_headers.py`.
- **Conventional Commits.** Types `feat|fix|docs|test|chore|ci|refactor`; scopes **`contracts · detector ·
  harness · edge · collector · evaders · arena · fleet · docs · ci · repo`**. Releases + changelog are
  generated from these.
- **commitlint gates PRs:** the subject must be **lowercase-start** and **≤100 chars** with a valid scope
  (an uppercase leading word/acronym — `SEO`, `GeoLite2` — fails).
- **Strict typing everywhere:** Python `mypy --strict`; TS `strict` + `noUncheckedIndexedAccess` +
  `exactOptionalPropertyTypes`; Go `go vet`-clean.
- **Tiered coverage:** core logic ≥95%; IO/integration components lower + e2e. Don't chase the number with
  brittle mocks.
- **Contracts are the only coupling.** Components speak the `contracts/` JSON Schemas over HTTP and **never
  import each other**.
- **Regen `task catalog` after any `contracts/rules/registry.yaml` rule change** — it rewrites
  `docs/detection-catalog.md`, and CI fails if it's stale.

## Working here — verify before committing

```sh
task ci          # headers · detector · harness · edge · collector — the full gate
# or per component:
cd detector && uv run ruff check . && uv run mypy && uv run pytest
cd edge && go vet ./... && go test ./... -cover      # needs Go, or docker golang:1.26-alpine
cd collector && pnpm run typecheck && pnpm run lint && pnpm test
```

Go and Node aren't installed in some environments — use Docker (`golang:1.26-alpine`, `node:22-alpine`).

**Gotchas that bite:**

- The **pre-commit hook runs ruff + mypy + headers ONLY — not pytest.** The detector's **95% coverage gate
  is real** (`--cov-fail-under` in `pyproject`), enforced by CI / `uv run pytest`. **Never pipe pytest
  through `| tail`** — it masks the coverage-fail exit code and green-washes a red run.
- **Confirm outward-facing actions** (creating/merging PRs, cutting releases) before doing them, unless the
  user has explicitly told you to proceed.

## Docs map

- [`docs/frontier.md`](docs/frontier.md) — the **live state** of the arms race (≤1 screen; reconcile on
  every axis close). If it disagrees with the radar, the radar's newest dated entry wins.
- [`docs/coherent-stack.md`](docs/coherent-stack.md) — the composed red-team morphing stack (the research
  output).
- [`docs/research-radar.md`](docs/research-radar.md) — the **append-only** rung log (exhaustive; the source
  of truth reconciled up into `frontier.md`). The phase roadmaps (`red-team-roadmap.md`,
  `adversary-emulation-roadmap.md`) are structured but drift.
- Component deep-dives: [`docs/arena.md`](docs/arena.md), [`evaders/README.md`](evaders/README.md),
  [`fleet/README.md`](fleet/README.md).
