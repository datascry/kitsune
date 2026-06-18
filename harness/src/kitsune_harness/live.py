# harness/live — assemble one scoreboard from the verdicts of live evader runs.
# Each evader prints a verdict JSON; this validates them into Verdicts and reuses the renderer.

"""Live scoreboard assembly.

The replay path (``scenarios``/``Harness``) scores fixtures in-process; this path collects the
verdicts that real evaders read back from a *running* detector and folds them into one dated
``Scoreboard`` — so the live arms-race runs render with the same table as everything else.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from kitsune_detector.models import Verdict

from .models import ScenarioResult, Scoreboard


def result_from_verdict(label: str, version: str, verdict_json: dict[str, Any]) -> ScenarioResult:
    """Validate an evader's verdict JSON into a ScenarioResult (dropping the evader-only ``mode``)."""
    data = dict(verdict_json)
    data.pop("mode", None)  # evader annotation, not part of the Verdict contract
    return ScenarioResult(scenario=label, version=version, verdict=Verdict.model_validate(data))


def build_board(
    entries: list[tuple[str, str, dict[str, Any]]],
    *,
    generated_at: datetime,
    ruleset_version: str,
) -> Scoreboard:
    """Build a Scoreboard from ``(label, version, verdict_json)`` entries."""
    results = [result_from_verdict(label, version, vj) for (label, version, vj) in entries]
    return Scoreboard(generated_at=generated_at, ruleset_version=ruleset_version, results=results)
