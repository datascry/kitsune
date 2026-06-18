# harness/liveboard — CLI: render a live scoreboard from evader verdict JSON files.
# Usage: python -m kitsune_harness.liveboard label=path.json ... ; label defaults to the JSON "mode".

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .live import build_board
from .scoreboard import render_markdown


def _parse_arg(arg: str) -> tuple[str, dict[str, Any]] | None:
    label, _, path = arg.partition("=")
    if not path:  # bare path → derive label from the JSON "mode" or the filename stem
        path, label = label, ""
    text = Path(path).read_text().strip()
    if not text:  # a failed/empty evader output must not abort the whole board
        return None
    try:
        data: dict[str, Any] = json.loads(text)
    except json.JSONDecodeError:
        return None
    return (label or data.get("mode") or Path(path).stem, data)


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI
    argv = sys.argv[1:] if argv is None else argv
    parsed = (_parse_arg(a) for a in argv)
    entries = [(label, "live", data) for label, data in (p for p in parsed if p is not None)]
    board = build_board(entries, generated_at=datetime.now(UTC), ruleset_version="live")
    print(render_markdown(board), end="")


if __name__ == "__main__":  # pragma: no cover
    main()
