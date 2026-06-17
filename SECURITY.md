# Security Policy

Kitsune is a **security research lab** that builds both bot detection and evasion. It is designed to
be self-contained and safe to run; this policy covers vulnerabilities in Kitsune itself and the
ethical boundaries of its red-team tooling.

## Reporting a vulnerability

Please report security issues privately via [GitHub Security Advisories](https://github.com/kitsune-lab/kitsune/security/advisories/new)
rather than a public issue. We aim to acknowledge within 5 business days. Include reproduction steps
and affected component(s) (`detector` / `edge` / `collector` / `harness`).

## Scope & ethical boundaries

The **evaders are dual-use**. Kitsune enforces a hard boundary, in code, not just docs:

- Evaders may target **only** (a) Kitsune's own detector and (b) the fixed public test endpoints in
  `harness/src/kitsune_harness/allowlist.py` (sannysoft, CreepJS, BrowserLeaks, tls.peet.ws,
  fingerprint.com demo, incolumitas).
- **Never** point an evader at a third-party or production site. No scraping, no credential use, no
  live DDoS. The self-contained arena *is* the ethics design.

Reports that amount to "the evaders can attack site X" where X is outside the allow-list are **out of
scope** — that is prevented by the allow-list, and bypassing it is the vulnerability we care about.

## Supply chain

- GitHub Actions are pinned by commit SHA; dependencies are watched by Dependabot.
- Secret scanning (gitleaks) runs in CI and pre-commit.
- An SBOM is generated on release.
- GPL/AGPL evader-side tooling is kept isolated from the permissively-licensed detector — a CI gate
  enforces this (see `docs/catalog.md` §14).
