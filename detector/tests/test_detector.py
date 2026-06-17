# tests/test_detector — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

from kitsune_detector.detector import Detector
from kitsune_detector.models import Label, Layer, Session, Source

from .conftest import FIXED, make_signal


def test_scores_human_as_clean(detector: Detector, human_session: Session) -> None:
    verdict = detector.score(human_session)
    assert verdict.label is Label.human
    assert verdict.score == 0.0
    assert verdict.contradictions == []
    assert verdict.scored_at == FIXED
    assert verdict.ruleset_version == detector.ruleset_version


def test_scores_bot_as_bot(detector: Detector, bot_session: Session) -> None:
    verdict = detector.score(bot_session)
    assert verdict.label is Label.bot
    assert verdict.score > 0.9
    assert verdict.incoherence_score > 0.0
    assert len(verdict.contradictions) >= 5
    # explainability: every contradiction carries evidence
    assert all(c.evidence for c in verdict.contradictions)


def test_ingest_and_score(detector: Detector) -> None:
    signals = [
        make_signal("z", Layer.browser, "webdriver", True, source=Source.collector),
        make_signal("z", Layer.network, "ja4_os_hint", "windows", source=Source.edge),
    ]
    verdicts = detector.ingest_and_score(signals)
    assert len(verdicts) == 1
    assert verdicts[0].session_id == "z"


def test_default_clock_is_timezone_aware(human_session: Session) -> None:
    verdict = Detector().score(human_session)  # no injected clock -> _utcnow
    assert verdict.scored_at.tzinfo is not None
