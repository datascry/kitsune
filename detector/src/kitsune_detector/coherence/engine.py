# detector/coherence/engine — generic evaluator over data-driven rules.
# Resolves each rule's reads against a session and emits contradictions.

"""The coherence engine — a generic evaluator over data-driven rules.

The engine knows *how* to evaluate (resolve a rule's reads against a session, run its predicate,
emit a contradiction). It knows nothing about *which* incoherences matter — that is the registry's
job. This separation is what keeps Kitsune maintainable as signals decay.
"""

from __future__ import annotations

from ..models import Contradiction, Layer, Session
from .predicates import PREDICATES
from .rules import CoherenceRule, RuleSet


class CoherenceEngine:
    def __init__(self, ruleset: RuleSet) -> None:
        self._ruleset = ruleset

    @property
    def ruleset_version(self) -> str:
        return self._ruleset.ruleset_version

    @staticmethod
    def _resolve(session: Session, ref: str) -> object:
        """Resolve a ``layer.kind`` read to its signal value, or MISSING."""
        layer_name, _, kind = ref.partition(".")
        return session.value(Layer(layer_name), kind)

    def _fire(self, session: Session, rule: CoherenceRule) -> bool:
        predicate = PREDICATES[rule.predicate]
        values = [self._resolve(session, ref) for ref in rule.reads]
        return predicate(values, rule.threshold)

    def evaluate(self, session: Session) -> list[Contradiction]:
        """Return every contradiction that fires for this session."""
        contradictions: list[Contradiction] = []
        for rule in self._ruleset.evaluable_rules:
            if self._fire(session, rule):
                contradictions.append(
                    Contradiction(
                        rule_id=rule.id,
                        layers=rule.layers,
                        detail=rule.title,
                        weight=rule.weight,
                        evidence=list(rule.reads),
                    )
                )
        return contradictions
