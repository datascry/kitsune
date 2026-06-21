# tests/test_rule_firing — every convicting present-predicate rule must fire when its read signal is present.
# Guards against a typo'd `reads` kind: a rule that can never fire is silently dead. Engine-level (no applicability).

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kitsune_detector.coherence.engine import CoherenceEngine
from kitsune_detector.coherence.rules import CoherenceRule, RuleStatus, load_registry
from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Layer, RuleCategory, Signal, Source

_CONVICTING = {RuleCategory.coherence, RuleCategory.automation, RuleCategory.artifact}
_RULESET = load_registry()
_ENGINE = CoherenceEngine(_RULESET)
_FIRE_RULES = [
    r
    for r in _RULESET.rules
    if r.status == RuleStatus.active and r.category in _CONVICTING and r.predicate == "present" and len(r.reads) == 1
]


@pytest.mark.parametrize("rule", _FIRE_RULES, ids=lambda r: r.id)
def test_convicting_present_rule_fires_on_its_read(rule: CoherenceRule) -> None:
    # Build a session carrying only this rule's single read signal as present; the engine must fire the rule.
    # A typo in `reads` (a kind the collector never emits) would make the rule unfireable — caught here.
    layer, _, kind = rule.reads[0].partition(".")
    sig = Signal(
        session_id="t",
        layer=Layer(layer),
        kind=kind,
        value=True,
        source=Source.collector,
        observed_at=datetime(2026, 6, 21, tzinfo=UTC),
    )
    session = group_signals([sig])[0]
    fired = {c.rule_id for c in _ENGINE.evaluate(session)}
    assert rule.id in fired, f"{rule.id} did not fire on its read {rule.reads[0]}=True"
