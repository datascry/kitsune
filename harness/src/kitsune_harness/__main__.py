# harness/__main__ — run the spine demo scoreboard.
# Replays the example sessions through the detector and prints the scoreboard.

"""Run the spine demo: replay the example sessions through the detector and print a scoreboard.

python -m kitsune_harness            # markdown to stdout
python -m kitsune_harness --json     # json to stdout
"""

from __future__ import annotations

import json
import sys

from kitsune_detector.contracts import contracts_dir

from .harness import Harness
from .scenarios import ReplayScenario
from .scoreboard import render_json, render_markdown


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI
    argv = sys.argv[1:] if argv is None else argv
    examples = contracts_dir() / "examples"
    scenarios = [
        ReplayScenario("vanilla", "0.1.0", examples / "session_human.json"),
        ReplayScenario("naive-bot", "0.1.0", examples / "session_bot.json"),
    ]
    board = Harness().run(scenarios)
    if "--json" in argv:
        print(json.dumps(render_json(board), indent=2))
    else:
        print(render_markdown(board), end="")


if __name__ == "__main__":  # pragma: no cover
    main()
