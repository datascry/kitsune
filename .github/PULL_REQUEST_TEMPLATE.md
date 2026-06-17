<!-- PR title must follow Conventional Commits, e.g. feat(detector): add JA4 coherence rule -->

## What & why

<!-- What does this change and why? Link issues. -->

## Component(s)

- [ ] contracts
- [ ] detector
- [ ] edge
- [ ] collector
- [ ] harness
- [ ] evaders
- [ ] docs / ci

## Checklist

- [ ] `task ci` is green (lint, type-check, tests, coverage gates)
- [ ] 2-line file headers present on new scripts (`scripts/check_headers.py`)
- [ ] Strict typing holds (mypy --strict / tsc strict / go vet)
- [ ] ADR added under `docs/adr/` for any significant design decision
- [ ] `CHANGELOG.md` _Unreleased_ updated if user-facing
- [ ] No evader points outside the ethics allow-list
