# tests/test_predicates — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

import pytest

from kitsune_detector.coherence.predicates import (
    PREDICATES,
    above_threshold,
    absent,
    below_threshold,
    equals,
    not_equal,
    not_equal_browser,
    present,
)
from kitsune_detector.models import MISSING


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, True), (False, False), ("x", True), ("", False), (MISSING, False), (None, False)],
)
def test_present(value: object, expected: bool) -> None:
    assert present([value], None) is expected
    assert absent([value], None) is (not expected)


def test_equals() -> None:
    assert equals(["a", "a"], None) is True
    assert equals(["a", "b"], None) is False
    assert equals([MISSING, "a"], None) is False


def test_not_equal() -> None:
    assert not_equal(["a", "b"], None) is True
    assert not_equal(["a", "a"], None) is False
    assert not_equal([MISSING, "a"], None) is False
    assert not_equal(["a", MISSING], None) is False


def test_below_threshold() -> None:
    assert below_threshold([0.1], 0.15) is True
    assert below_threshold([0.2], 0.15) is False
    assert below_threshold([0.1], None) is False
    assert below_threshold([MISSING], 0.15) is False
    assert below_threshold([True], 0.15) is False  # bool is not a numeric reading
    assert below_threshold(["x"], 0.15) is False


def test_above_threshold() -> None:
    assert above_threshold([0.9], 0.5) is True
    assert above_threshold([0.1], 0.5) is False
    assert above_threshold([0.9], None) is False


def test_not_equal_browser() -> None:
    # A Chromium-family UA (Edge/Brave/Opera) matches the 'chrome' network engine-hint → no contradiction.
    assert not_equal_browser(["chrome", "edge"], None) is False  # real Edge: ja4 hint chrome vs UA edge
    assert not_equal_browser(["chrome", "brave"], None) is False
    assert not_equal_browser(["chrome", "chrome"], None) is False
    # Cross-ENGINE pairings still fire (the actual spoof signal).
    assert not_equal_browser(["chrome", "firefox"], None) is True  # spoof-ua: chrome TLS, Firefox UA
    assert not_equal_browser(["chrome", "safari"], None) is True  # ios-ua-spoof
    assert not_equal_browser(["safari", "chrome"], None) is True  # webkit-ua-spoof
    # Missing data is never a contradiction.
    assert not_equal_browser([MISSING, "edge"], None) is False
    assert not_equal_browser(["chrome", MISSING], None) is False


def test_registry_complete() -> None:
    assert set(PREDICATES) == {
        "present",
        "absent",
        "equals",
        "not_equal",
        "not_equal_browser",
        "below_threshold",
        "above_threshold",
    }
