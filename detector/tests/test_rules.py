# tests/test_rules — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

import pytest
from pydantic import ValidationError

from kitsune_detector.coherence.rules import CoherenceRule, RuleSet, RuleStatus, load_registry
from kitsune_detector.models import Layer


def _rule(**kw: object) -> CoherenceRule:
    base: dict[str, object] = {
        "id": "x.y",
        "title": "t",
        "layers": [Layer.browser],
        "reads": ["browser.webdriver"],
        "predicate": "present",
        "weight": 0.5,
        "status": "active",
    }
    base.update(kw)
    return CoherenceRule(**base)  # type: ignore[arg-type]


def test_equals_needs_two_reads() -> None:
    with pytest.raises(ValidationError):
        _rule(predicate="equals", reads=["browser.a"])


def test_threshold_predicate_needs_threshold() -> None:
    with pytest.raises(ValidationError):
        _rule(predicate="below_threshold", reads=["behavioral.x"])


def test_evaluable_property() -> None:
    assert _rule(status="active").evaluable is True
    assert _rule(status="retired").evaluable is False


def test_ruleset_filters_retired() -> None:
    rs = RuleSet(
        ruleset_version="9.9.9",
        rules=[_rule(id="a.a"), _rule(id="b.b", status="retired")],
    )
    assert [r.id for r in rs.evaluable_rules] == ["a.a"]


def test_load_registry() -> None:
    rs = load_registry()
    assert rs.ruleset_version
    assert any(r.id == "br.webdriver_present" for r in rs.rules)
    assert all(isinstance(r.status, RuleStatus) for r in rs.rules)
