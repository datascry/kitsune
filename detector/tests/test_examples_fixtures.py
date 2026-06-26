# tests/test_examples_fixtures — detector test module.
# Asserts behaviour and edge cases for the unit under test.

"""The contract example fixtures are the test oracle: they must validate, round-trip, and score."""

from __future__ import annotations

import pytest

from kitsune_detector.contracts import validate
from kitsune_detector.detector import Detector
from kitsune_detector.models import Label, Session

from .conftest import load_example


@pytest.mark.parametrize("name", ["session_human.json", "session_bot.json"])
def test_example_validates_and_round_trips(name: str) -> None:
    raw = load_example(name)
    validate(raw, "session.schema.json")
    session = Session.model_validate(raw)
    # model -> wire -> schema is stable
    validate(session.model_dump(mode="json"), "session.schema.json")


def test_verdict_round_trips_through_schema(detector: Detector, bot_session: Session) -> None:
    verdict = detector.score(bot_session)
    validate(verdict.model_dump(mode="json"), "verdict.schema.json")


def test_fixtures_score_as_labelled(detector: Detector) -> None:
    human = Session.model_validate(load_example("session_human.json"))
    bot = Session.model_validate(load_example("session_bot.json"))
    assert detector.score(human).label is Label.human
    assert detector.score(bot).label is Label.bot


@pytest.mark.parametrize(
    ("name", "schema"),
    [
        ("challenge_memory_hard.json", "challenge.schema.json"),
        ("finding_pow_cost.json", "finding.schema.json"),
    ],
)
def test_arena_contract_fixtures_validate(name: str, schema: str) -> None:
    # The arena/reporting contracts (challenge, finding) gain golden fixtures that must validate, so the
    # schemas are exercised before any arena code consumes them (contracts-first, like session/verdict).
    validate(load_example(name), schema)
