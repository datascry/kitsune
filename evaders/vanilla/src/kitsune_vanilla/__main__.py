# evaders/vanilla/__main__ — run the vanilla evader once against the live stack.
# Reads KITSUNE_EDGE / KITSUNE_DETECTOR, prints the detector's verdict as JSON.

from __future__ import annotations

import json
import os

from .runner import build_client, run_once


def main() -> None:  # pragma: no cover - thin CLI
    edge = os.environ.get("KITSUNE_EDGE", "https://localhost:8443/healthz")
    detector = os.environ.get("KITSUNE_DETECTOR", "http://localhost:8080")
    with build_client() as client:
        print(json.dumps(run_once(edge, detector, client=client), indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()
