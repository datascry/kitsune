# detector/coherence/rules — coherence rules as data.
# Loads + validates the registry; models a CoherenceRule and RuleSet.

"""Coherence rules — knowledge as data, loaded and validated from the contracts registry."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..contracts import load_rule_registry
from ..models import Layer, RuleCategory


class RuleStatus(StrEnum):
    active = "active"
    experimental = "experimental"
    retired = "retired"


class CoherenceRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    layers: list[Layer]
    reads: list[str] = Field(min_length=1)
    predicate: str
    threshold: float | None = None
    weight: float = Field(ge=0.0, le=1.0)
    status: RuleStatus
    category: RuleCategory = RuleCategory.coherence
    added: str | None = None
    last_validated: str | None = None
    source: str | None = None

    @model_validator(mode="after")
    def _check_predicate_arity(self) -> CoherenceRule:
        if self.predicate in ("equals", "not_equal", "not_equal_browser") and len(self.reads) < 2:
            raise ValueError(f"rule {self.id}: predicate {self.predicate} needs >=2 reads")
        if self.predicate in ("below_threshold", "above_threshold") and self.threshold is None:
            raise ValueError(f"rule {self.id}: predicate {self.predicate} needs a threshold")
        return self

    @property
    def evaluable(self) -> bool:
        """Retired rules are kept for history but never evaluated."""
        return self.status is not RuleStatus.retired


class RuleSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ruleset_version: str
    rules: list[CoherenceRule]

    @property
    def evaluable_rules(self) -> list[CoherenceRule]:
        return [r for r in self.rules if r.evaluable]


def load_registry() -> RuleSet:
    """Load + validate the coherence-rule registry from ``contracts/rules/registry.yaml``."""
    version, raw_rules = load_rule_registry()
    return RuleSet(ruleset_version=version, rules=[CoherenceRule(**r) for r in raw_rules])
