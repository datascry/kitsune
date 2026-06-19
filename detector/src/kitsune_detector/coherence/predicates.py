# detector/coherence/predicates — the fixed predicate vocabulary.
# Pure functions deciding when a rule fires over resolved signal values.

"""Predicates — the small, fixed vocabulary the data-driven rules are built from.

Each predicate answers one question: *given the resolved signal values this rule reads, does the
contradiction fire?* Keeping this set tiny and pure is what lets the knowledge live in YAML instead
of code. New knowledge is a new registry entry; only genuinely new *shapes* of comparison need a new
predicate here.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..models import MISSING

#: A predicate takes the ordered resolved values for a rule's ``reads`` plus an optional threshold,
#: and returns True when the contradiction fires.
Predicate = Callable[[list[Any], float | None], bool]


def _present(value: Any) -> bool:
    """Truthy and not the MISSING sentinel."""
    return value is not MISSING and bool(value)


def _is_number(value: Any) -> bool:
    # bool is an int subclass; a boolean is never a numeric reading.
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def present(values: list[Any], _threshold: float | None) -> bool:
    return _present(values[0])


def absent(values: list[Any], _threshold: float | None) -> bool:
    return not _present(values[0])


def equals(values: list[Any], _threshold: float | None) -> bool:
    a, b = values[0], values[1]
    return a is not MISSING and b is not MISSING and a == b


def not_equal(values: list[Any], _threshold: float | None) -> bool:
    # Only fire when BOTH sides are present — missing data is not a contradiction.
    a, b = values[0], values[1]
    return a is not MISSING and b is not MISSING and a != b


# Chromium-family browsers (Edge, Brave, Opera, Vivaldi, …) all ship the SAME Chromium TLS/HTTP-2 engine, so a
# network engine-hint of "chrome" is coherent with ANY of their UAs — only a CROSS-ENGINE pairing (Chromium
# stack under a Firefox/Safari UA) is a contradiction. Collapse the family to its engine before comparing so a
# real Microsoft Edge (ja4/h2 hint "chrome", ua_browser "edge") is not falsely flagged. GROUNDED on real Edge
# 149. v0.74.30.
_BROWSER_ENGINE = {
    "edge": "chrome",
    "brave": "chrome",
    "opera": "chrome",
    "vivaldi": "chrome",
    "samsung": "chrome",
    "chromium": "chrome",
}


def _engine_family(v: Any) -> Any:
    return _BROWSER_ENGINE.get(v, v) if isinstance(v, str) else v


def not_equal_browser(values: list[Any], _threshold: float | None) -> bool:
    """``not_equal`` but engine-family-aware: a Chromium-family UA matches a 'chrome' network engine-hint."""
    a, b = values[0], values[1]
    return a is not MISSING and b is not MISSING and _engine_family(a) != _engine_family(b)


def below_threshold(values: list[Any], threshold: float | None) -> bool:
    v = values[0]
    return threshold is not None and _is_number(v) and v < threshold


def above_threshold(values: list[Any], threshold: float | None) -> bool:
    v = values[0]
    return threshold is not None and _is_number(v) and v > threshold


PREDICATES: dict[str, Predicate] = {
    "present": present,
    "absent": absent,
    "equals": equals,
    "not_equal": not_equal,
    "not_equal_browser": not_equal_browser,
    "below_threshold": below_threshold,
    "above_threshold": above_threshold,
}
