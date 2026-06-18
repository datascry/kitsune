# tests/test_report — tests for the VirusTotal-style detection aggregator.
# Asserts the coverage map (which engines fire per sample) and the rendered matrix.

from __future__ import annotations

from kitsune_detector.contracts import contracts_dir
from kitsune_detector.detector import Detector
from kitsune_detector.models import Session

from kitsune_harness.report import (
    coverage,
    evaluable_detectors,
    render_categories,
    render_matrix,
)


def _examples() -> list[tuple[str, Session]]:
    ex = contracts_dir() / "examples"
    return [
        ("human", Session.model_validate_json((ex / "session_human.json").read_text())),
        ("bot", Session.model_validate_json((ex / "session_bot.json").read_text())),
    ]


def test_evaluable_detectors_nonempty() -> None:
    assert len(evaluable_detectors()) >= 10


def test_coverage_flags_bot_not_human(detector: Detector) -> None:
    _detectors, fired, verdicts = coverage(detector, _examples())
    assert fired["human"] == set()
    assert "br.webdriver_present" in fired["bot"]
    assert verdicts["bot"].label.value == "bot"
    assert verdicts["human"].label.value == "human"


def test_render_matrix(detector: Detector) -> None:
    detectors, fired, verdicts = coverage(detector, _examples())
    md = render_matrix(detectors, fired, verdicts)
    assert "| Detector | layer | human | bot | catches |" in md
    assert "br.webdriver_present" in md
    assert "**flagged**" in md and "**verdict**" in md
    assert "✓" in md and "·" in md


def test_render_categories(detector: Detector) -> None:
    _detectors, _fired, verdicts = coverage(detector, _examples())
    md = render_categories(verdicts)
    # The bot fixture trips automation (webdriver) and environment tells; the header lists every class.
    assert "Detection class" in md
    assert "coherence" in md and "environment" in md and "automation" in md
    assert "`bot`" in md and "`human`" in md


def test_zero_catch_and_gaps(detector: Detector) -> None:
    from kitsune_harness.report import render_gaps, zero_catch

    detectors, fired, _ = coverage(detector, _examples())
    # Only a handful of rules fire on the human/bot examples; most are "gaps".
    gaps = zero_catch(detectors, fired)
    assert "br.webdriver_present" not in gaps  # the bot example triggers it
    assert isinstance(gaps, list) and len(gaps) > 5
    assert "Coverage gaps" in render_gaps(detectors, fired)
