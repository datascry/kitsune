# harness/corpus — score a corpus of recorded sessions in-process (the fast blue-side loop).
# Edit detection rules, re-score the real recordings in <1s, see the scoreboard diff — no docker.

"""Recorded-session corpus.

The live docker run is ground truth but slow; the inner iteration loop scores a directory of
recorded ``Session`` JSONs in-process with the *current* ruleset. Capture each evader once (via the
detector's ``/session/{id}``), then iterate detection rules against the corpus instantly. Refresh the
corpus from periodic live runs.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kitsune_detector.detector import Detector
from kitsune_detector.models import Session

from .models import ScenarioResult, Scoreboard
from .scoreboard import render_markdown

DEFAULT_CORPUS = "corpus/sessions"


def load_corpus(directory: str | Path) -> list[tuple[str, Session]]:
    """Load every ``*.json`` in ``directory`` as a (name, Session), name = filename stem, sorted."""
    out: list[tuple[str, Session]] = []
    for path in sorted(Path(directory).glob("*.json")):
        out.append((path.stem, Session.model_validate_json(path.read_text())))
    return out


def score_corpus(
    detector: Detector,
    corpus: list[tuple[str, Session]],
    *,
    generated_at: datetime,
    ruleset_version: str,
) -> Scoreboard:
    """Score every recorded session with the current ruleset into one Scoreboard."""
    results = [
        ScenarioResult(scenario=name, version="corpus", verdict=detector.score(session))
        for name, session in corpus
    ]
    return Scoreboard(generated_at=generated_at, ruleset_version=ruleset_version, results=results)


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI
    import sys

    argv = sys.argv[1:] if argv is None else argv
    directory = argv[0] if argv else DEFAULT_CORPUS
    detector = Detector()
    board = score_corpus(
        detector,
        load_corpus(directory),
        generated_at=datetime.now(UTC),
        ruleset_version=detector.ruleset_version,
    )
    print(render_markdown(board), end="")


if __name__ == "__main__":  # pragma: no cover
    main()
