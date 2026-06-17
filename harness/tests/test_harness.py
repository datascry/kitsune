# tests/test_harness — harness test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

import pytest
from kitsune_detector.models import Layer, Signal, Source

from kitsune_harness.harness import Harness
from kitsune_harness.scenarios import ReplayScenario

from .conftest import FIXED, FakeScenario


def _sig(session_id: str) -> Signal:
    return Signal(
        session_id=session_id,
        layer=Layer.browser,
        kind="webdriver",
        value=True,
        source=Source.collector,
        observed_at=FIXED,
    )


def test_run_builds_scoreboard(
    detector, fixed_clock, human_scenario: ReplayScenario, bot_scenario: ReplayScenario
) -> None:
    board = Harness(detector, clock=fixed_clock).run([human_scenario, bot_scenario])
    assert board.generated_at == FIXED
    assert board.ruleset_version == detector.ruleset_version
    labels = {r.scenario: r.verdict.label.value for r in board.results}
    assert labels == {"vanilla": "human", "naive-bot": "bot"}


def test_scenario_must_be_single_session(detector, fixed_clock) -> None:
    bad = FakeScenario("multi", "0.1.0", [_sig("a"), _sig("b")])
    with pytest.raises(ValueError, match="expected exactly 1"):
        Harness(detector, clock=fixed_clock).run([bad])


def test_defaults_construct_detector_and_clock(human_scenario: ReplayScenario) -> None:
    board = Harness().run([human_scenario])  # default Detector() + _utcnow
    assert board.generated_at.tzinfo is not None
    assert board.ruleset_version
