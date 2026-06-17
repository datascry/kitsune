# tests/test_ingest — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

from datetime import timedelta

from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Layer, Source

from .conftest import FIXED, make_signal


def test_group_empty() -> None:
    assert group_signals([]) == []


def test_group_correlates_by_session() -> None:
    later = FIXED + timedelta(seconds=5)
    signals = [
        make_signal("a", Layer.network, "ja4", "x", source=Source.edge, at=FIXED),
        make_signal("b", Layer.network, "ja4", "y", source=Source.edge, at=FIXED),
        make_signal("a", Layer.browser, "webdriver", True, source=Source.collector, at=later),
    ]
    sessions = group_signals(signals)

    assert [s.session_id for s in sessions] == ["a", "b"]  # first-seen order preserved
    session_a = sessions[0]
    assert session_a.request_count == 1  # one edge-sourced signal
    assert session_a.first_seen == FIXED
    assert session_a.last_seen == later
    assert session_a.value(Layer.browser, "webdriver") is True
