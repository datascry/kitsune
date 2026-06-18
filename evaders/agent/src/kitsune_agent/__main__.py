# evaders/agent/__main__ — run the claude-driven agent once against the live stack.
# Reads KITSUNE_BROWSER_WS / KITSUNE_EDGE / KITSUNE_DETECTOR; prints the verdict JSON.

from __future__ import annotations

import json
import os

from .runner import run_session


def main() -> None:  # pragma: no cover - thin CLI
    ws = os.environ["KITSUNE_BROWSER_WS"]
    edge = os.environ.get("KITSUNE_EDGE", "https://edge:8443/")
    detector = os.environ.get("KITSUNE_DETECTOR", "http://localhost:8080")
    steps = int(os.environ.get("KITSUNE_AGENT_STEPS", "2"))
    print(json.dumps(run_session(ws, edge, detector, steps=steps), indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()
