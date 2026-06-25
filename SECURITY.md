# Security Policy

Kitsune is a **security research lab** that builds both bot detection and evasion. It is designed to
be self-contained and safe to run; this policy covers vulnerabilities in Kitsune itself and the
ethical boundaries of its red-team tooling.

## Reporting a vulnerability

Please report security issues privately via [GitHub Security Advisories](https://github.com/datascry/kitsune/security/advisories/new)
rather than a public issue. We aim to acknowledge within 5 business days. Include reproduction steps
and affected component(s) (`detector` / `edge` / `collector` / `harness`).

## Scope & ethical boundaries

The **evaders are dual-use**. Kitsune enforces a hard boundary, in code, not just docs:

- Evaders may target **only** (a) Kitsune's own detector and (b) the fixed public test endpoints
  enumerated in `harness/src/kitsune_harness/allowlist.py` (`ALLOWED_TEST_HOSTS`) — dedicated
  bot/fingerprint self-test pages and vendor-official challenge demos, never a production site. That
  file is the single source of truth; consult it rather than a copy here, which can drift. Host
  matching is **exact** (an over-broad host like `www.google.com` is deliberately excluded).
- **Never** point an evader at a third-party or production site. No scraping, no credential use, no
  live DDoS. The self-contained arena *is* the ethics design.

**Verified-agent allow-list (Web Bot Auth).** A session presenting a cryptographically *valid* RFC 9421
Web Bot Auth signature is allow-listed as a known-good bot (`Label.verified`, via
`scoring.verified_agent`), overriding the automation signals it honestly trips. This is **only as strong
as the signing key's secrecy.** The lab seeds the *public* RFC 9421 test key, so **in-sandbox any client
can mint a "verified" agent** (the demonstrated bypass: go-tls `KS_WEBBOTAUTH=valid`) — this is an
intentional in-sandbox demo, not a fieldable trust boundary. A *forged* signature trips
`net.web_bot_auth_invalid` and is convicted, never allow-listed. Production must trust only real agent
directories whose private keys stay secret.

Reports that amount to "the evaders can attack site X" where X is outside the allow-list are **out of
scope** — that is prevented by the allow-list, and bypassing it is the vulnerability we care about.

## Cross-site scripting (the public pages)

The detector serves a public site (`kitsune.id`) that renders **attacker-influenced input** — the
visitor's own User-Agent, WebGL renderer, screen, IP, etc. The audited disposition:

- **Client render (live page):** every fingerprint value is HTML-escaped (`esc()`) before it touches
  `innerHTML`; a crafted User-Agent can only ever self-XSS the requester, and even that is escaped.
- **Server render (drill-downs / doc pages):** all interpolation goes through `html.escape`
  (canonical/OG URLs included), and rendered rule-ids/slugs are sourced from the trusted registry, not
  the raw path param. The drill-down routes also 404 any id/slug not in the registry.
- **Stored signals:** `/inspect` is cookie-scoped (you only ever read your own session) and returns
  JSON; `/session`, `/verdict`, `/scoreboard` are admin-gated (`KITSUNE_ADMIN_TOKEN`). No stored
  signal is reflected as HTML to another visitor.

## Triaged code-scanning findings

Reviewed and dispositioned (see the git history for the audit pass):

- **`py/reflective-xss` (detector drill-downs) — FIXED:** `html.escape` sanitizer + trusted-registry ids.
- **`go/disabled-certificate-check` (evaders) — accepted:** the red-team tools connect only to the
  allow-listed, self-signed **lab** edge (`InsecureSkipVerify`, `nolint`-documented); they transmit no
  secrets and never target a third-party host. Production `detector`/`edge` verify real certs.
- **`go/uncontrolled-allocation-size` (`evaders/pow`) — false positive:** the count is clamped to
  `[1, MaxManySmallCount]` before the allocation.
- **Scorecard `PinnedDependencies` (evader Dockerfiles) — accepted:** red-team build tooling; the
  production `detector`/`edge` images are `distroless`/`slim`.

## Supply chain

- GitHub Actions are pinned by commit SHA; dependencies are watched by Dependabot.
- Secret scanning (gitleaks) runs in CI and pre-commit.
- An SBOM is generated on release.
- GPL/AGPL evader-side tooling is kept isolated from the permissively-licensed detector — a CI gate
  enforces this (see `docs/catalog.md` §14).
