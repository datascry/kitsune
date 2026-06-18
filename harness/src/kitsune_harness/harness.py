# harness/harness — run scenarios against the detector.
# Scores each scenario into a ScenarioResult and assembles a Scoreboard.

"""The harness — run scenarios against the detector and assemble a scoreboard."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime

from kitsune_detector.detector import Detector
from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Verdict

from .models import ScenarioResult, Scoreboard
from .scenarios import Scenario

Clock = Callable[[], datetime]


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Harness:
    def __init__(self, detector: Detector | None = None, *, clock: Clock = _utcnow) -> None:
        self._detector = detector or Detector()
        self._clock = clock

    def _score_scenario(self, scenario: Scenario) -> ScenarioResult:
        signals = scenario.collect()
        sessions = group_signals(signals)
        if len(sessions) != 1:
            raise ValueError(f"scenario {scenario.name!r} produced {len(sessions)} sessions; expected exactly 1")
        verdict: Verdict = self._detector.score(sessions[0])
        return ScenarioResult(scenario=scenario.name, version=scenario.version, verdict=verdict)

    def run(self, scenarios: Iterable[Scenario]) -> Scoreboard:
        """Score every scenario and return a dated, reproducible scoreboard."""
        results = [self._score_scenario(s) for s in scenarios]
        return Scoreboard(
            generated_at=self._clock(),
            ruleset_version=self._detector.ruleset_version,
            results=results,
        )
