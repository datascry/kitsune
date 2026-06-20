# harness/live_coordination — run coordination grading against the LIVE detector's session store.
# Polls /scoreboard + /session/{id} over HTTP, rebuilds the corpus, reuses score_corpus/render_coordination.

"""Live coordination harness.

The coordination detector (``coordination.py``) is validated offline over frozen ``corpus/`` fleets. This
module is the missing *live* wiring: instead of reading fixtures from disk, it pulls the running detector's
real session store over the HTTP contract (``GET /scoreboard`` enumerates the session ids, ``GET
/session/{id}`` returns each correlated session) and feeds them straight into the SAME tested
``score_corpus`` / ``render_coordination`` path. So an operator can point it at the live edge→detector stack
and see the coordinated-fleet view the per-session scoreboard cannot show.

The HTTP fetch is injected (``get_json``) so the corpus-building + grading is tested hermetically without a
running detector. The truly-live half that stays blocked is real residential-proxy egress (for the
IP-reputation disambiguator) — this wires everything the sandbox CAN exercise: the fp/trace-collision and
JS-divergence coordination signals over real captured sessions.
"""

from __future__ import annotations

import json
import os
import urllib.request
from collections.abc import Callable
from typing import Any

from kitsune_detector.models import Session

from .coordination import FleetVerdict, render_coordination, score_corpus

JsonGetter = Callable[[str], Any]

DEFAULT_DETECTOR = os.environ.get("KITSUNE_DETECTOR", "http://localhost:8080")


def _http_get_json(url: str) -> Any:  # pragma: no cover - thin network shim
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.load(resp)


def fetch_live_corpus(base_url: str, *, get_json: JsonGetter = _http_get_json) -> list[tuple[str, Session]]:
    """Pull every correlated session the live detector holds into a ``(session_id, Session)`` corpus.

    Enumerates session ids from ``/scoreboard`` (the verdict list) and fetches each full session from
    ``/session/{id}``. A session that 404s or fails to validate is skipped (the detector may have evicted it
    between the two calls), never aborting the whole board.
    """
    base = base_url.rstrip("/")
    verdicts = get_json(f"{base}/scoreboard")
    corpus: list[tuple[str, Session]] = []
    for verdict in verdicts:
        sid = verdict.get("session_id")
        if not sid:
            continue
        try:
            corpus.append((sid, Session.model_validate(get_json(f"{base}/session/{sid}"))))
        except Exception:
            continue
    return corpus


def score_live(base_url: str, *, get_json: JsonGetter = _http_get_json) -> list[FleetVerdict]:
    """Fetch the live corpus and grade its JA4 clusters into fleet verdicts (strongest first)."""
    return score_corpus(fetch_live_corpus(base_url, get_json=get_json))


def render_live(base_url: str, *, get_json: JsonGetter = _http_get_json) -> str:
    """Fetch the live corpus and render the coordination board as markdown."""
    return render_coordination(fetch_live_corpus(base_url, get_json=get_json))


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI
    import sys

    argv = sys.argv[1:] if argv is None else argv
    base = argv[0] if argv else DEFAULT_DETECTOR
    print(render_live(base), end="")


if __name__ == "__main__":  # pragma: no cover
    main()
