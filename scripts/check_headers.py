#!/usr/bin/env python3
# scripts/check_headers — enforce the 2-line machine-scannable file header convention.
# Every script's first two comment lines say what it is / what it does, so agents can map by querying them.

"""Fail if any source file is missing the mandatory 2-line header.

Convention: the first two non-shebang lines of every script are comments; line 1 contains an em
dash (`—`) separating an identifier from a one-line "what it is", and line 2 says "what it does".
Run: ``python scripts/check_headers.py`` (also wired into pre-commit + CI).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Languages we treat as "scripts" (configs/JSON/Markdown are exempt — JSON can't carry comments).
EXTENSIONS = {".py", ".go", ".ts", ".tsx", ".js", ".mjs", ".sh"}
COMMENT_PREFIXES = ("#", "//")
SKIP_DIRS = {".git", ".venv", "node_modules", "dist", "coverage", "vendor", "__pycache__"}
SKIP_NAMES = {"pnpm-lock.yaml", "go.sum"}


def is_comment(line: str) -> bool:
    return line.lstrip().startswith(COMMENT_PREFIXES)


def has_valid_header(path: Path) -> bool:
    lines = path.read_text(encoding="utf-8").splitlines()
    # Drop a leading shebang.
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    if len(lines) < 2:
        return False
    return is_comment(lines[0]) and is_comment(lines[1]) and "—" in lines[0]


def iter_source_files(root: Path):
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix in EXTENSIONS and path.name not in SKIP_NAMES:
            yield path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    bad = [str(p.relative_to(root)) for p in iter_source_files(root) if not has_valid_header(p)]
    if bad:
        print("Missing/invalid 2-line header in:", file=sys.stderr)
        for path in sorted(bad):
            print(f"  {path}", file=sys.stderr)
        print(f"\n{len(bad)} file(s). See scripts/check_headers.py for the convention.", file=sys.stderr)
        return 1
    print("All source files carry a valid 2-line header.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
