# tests/test_ingest — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

from datetime import timedelta

from kitsune_detector.ingest import group_signals, merge_sessions
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


def test_merge_accumulates_layers() -> None:
    net = make_signal("a", Layer.network, "ja4", "x", source=Source.edge, at=FIXED)
    later = FIXED + timedelta(seconds=1)
    web = make_signal("a", Layer.browser, "webdriver", True, source=Source.collector, at=later)
    merged = merge_sessions(group_signals([net])[0], group_signals([web])[0])
    assert merged.value(Layer.network, "ja4") == "x"
    assert merged.value(Layer.browser, "webdriver") is True
    assert merged.request_count == 1  # one edge-sourced signal


def test_merge_keeps_latest_per_kind() -> None:
    old = make_signal("a", Layer.browser, "ua_browser", "chrome", at=FIXED)
    new = make_signal("a", Layer.browser, "ua_browser", "firefox", at=FIXED + timedelta(seconds=5))
    merged = merge_sessions(group_signals([old])[0], group_signals([new])[0])
    assert merged.value(Layer.browser, "ua_browser") == "firefox"
