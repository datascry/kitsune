#!/usr/bin/env python3
# scripts/check_license_isolation — keep copyleft evader tooling out of the permissive core.
# Fails if detector/harness/edge/collector/contracts reference evaders or known GPL/AGPL packages.

"""Enforce the license boundary from docs/catalog.md §14.

The detector and its peers are MIT/permissive; several red-side tools are GPL/AGPL and must stay
isolated in ``evaders/``. This check fails CI if the permissive core imports the evader tree or
depends on a known-copyleft package.
"""

from __future__ import annotations

import re
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


# An actual import of the evaders tree — Python `from/import evaders…`, or a JS/TS `from`/`require`/
# `import(...)` whose module path contains an `evaders/` segment. Matches imports, not prose: the old
# check flagged any line with both "evaders" and the English word "from" (e.g. a docstring), a false
# positive. A copyleft marker likewise only matters as a real dependency — an import/require or a
# manifest dependency key (pyproject/package.json) — not as a scoreboard label or comment.
_EVADER_IMPORT = re.compile(
    r"^\s*(?:from|import)\s+evaders\b"
    r"|(?:from\s+|require\s*\(\s*|import\s*\(\s*)['\"][^'\"]*\bevaders/",
)


def _imports_marker(line: str, marker: str, is_manifest: bool) -> bool:
    m = re.escape(marker)
    if (
        re.search(rf"^\s*(?:from|import)\s+{m}\b", line)  # python import
        or re.search(rf"(?:from\s+|require\s*\(\s*|import\s*\(\s*)['\"]{m}\b", line)  # js/ts import
    ):
        return True
    # The bare `marker:` / `marker =` dependency-KEY heuristic is only valid in a manifest. In source it
    # would flag a plain dict literal (e.g. an evader-description map keyed `"nodriver":`) — prose, not a
    # dependency. A real copyleft dep in the core still surfaces in pyproject.toml / package.json.
    return is_manifest and bool(re.search(rf"^\s*['\"]?{m}['\"]?\s*[:=]", line))


def offending_lines(path: Path) -> list[str]:
    is_manifest = path.name in {"package.json", "pyproject.toml"} or path.suffix == ".toml"
    hits: list[str] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if _EVADER_IMPORT.search(line):
            hits.append(f"{path}:{lineno}: core imports evaders ({line.strip()})")
        low = line.lower()
        for marker in COPYLEFT_MARKERS:
            if marker in low and _imports_marker(low, marker, is_manifest):
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
