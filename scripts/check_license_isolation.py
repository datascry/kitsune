#!/usr/bin/env python3
# scripts/check_license_isolation — keep copyleft evader tooling out of the permissive core.
# Fails if detector/harness/edge/collector/contracts reference evaders or known GPL/AGPL packages.

"""Enforce the license boundary from docs/catalog.md §14.

The detector and its peers are MIT/permissive; several red-side tools are GPL/AGPL and must stay
isolated in ``evaders/``. This check fails CI if the permissive core imports the evader tree or
depends on a known-copyleft package.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Core (permissive) areas that must NOT pull in copyleft / evader code.
CORE_DIRS = ["detector", "harness", "edge", "collector", "contracts"]

# Known GPL/AGPL packages from the catalog that must never appear in core dependencies.
COPYLEFT_MARKERS = (
    "cycletls",
    "undetected-chromedriver",
    "undetected_chromedriver",
    "mcaptcha",
    "skyvern",
    "nodriver",
    "pyclick",
)

SCAN_SUFFIXES = {".py", ".go", ".ts", ".tsx", ".js", ".mjs", ".toml"}
SKIP_DIRS = {".git", ".venv", "node_modules", "dist", "coverage", "__pycache__"}


def offending_lines(path: Path) -> list[str]:
    hits: list[str] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        low = line.lower()
        if "evaders" in low and ("import" in low or "from" in low or "require" in low):
            hits.append(f"{path}:{lineno}: core references evaders ({line.strip()})")
        if any(marker in low for marker in COPYLEFT_MARKERS):
            hits.append(f"{path}:{lineno}: copyleft dependency ({line.strip()})")
    return hits


def main() -> int:
    problems: list[str] = []
    for core in CORE_DIRS:
        base = ROOT / core
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.is_file() and path.suffix in SCAN_SUFFIXES:
                problems.extend(offending_lines(path))
    if problems:
        print("License isolation violated:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    print("License isolation holds: core is free of evader/copyleft references.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
