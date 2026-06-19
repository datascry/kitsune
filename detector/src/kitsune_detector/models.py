# detector/models — Pydantic models mirroring the JSON-Schema contracts.
# The Signal/Session/Verdict nouns the detector speaks; round-trip to/from the wire format.

"""Pydantic models mirroring the JSON-Schema contracts.

These are the nouns the whole detector speaks. They round-trip to/from the wire format defined in
``contracts/*.schema.json`` via ``model_dump(mode="json")`` / ``model_validate``.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .config import SCHEMA_VERSION

#: Sentinel for "this signal was not present in the session". Distinct from a signal whose value is
#: ``None`` / ``False`` — the engine treats *missing* and *falsy* differently for some predicates.
MISSING: Any = object()


class Layer(StrEnum):
    network = "network"
    browser = "browser"
    behavioral = "behavioral"
    reputation = "reputation"


class Source(StrEnum):
    edge = "edge"
    collector = "collector"
    detector = "detector"


class Label(StrEnum):
    human = "human"
    suspicious = "suspicious"
    bot = "bot"


class RuleCategory(StrEnum):
    """What *kind* of tell a rule is — the detection class, validated against a no-spoof baseline.

    The core thesis is ``coherence`` (cross-vector contradictions). The others are honest about
    rules that are not coherence checks: ``environment`` and ``automation`` tells also fire on a
    stock headless browser, so they flag a stripped/automated environment rather than spoofing.
    """

    coherence = "coherence"  # cross-vector contradiction — the thesis core
    environment = "environment"  # capability absent (stripped/headless) — fires on stock headless too
    automation = "automation"  # automation-framework surface (webdriver, CDP artifacts)
    artifact = "artifact"  # anti-detect implementation flaw (spoofing placeholder, injected addon)
    behavioral = "behavioral"  # behavioral / input signals
    reputation = "reputation"  # network reputation (datacenter ASN, proxy exit)
    prevalence = "prevalence"  # statistical likelihood (improbable-but-coherent joint) — corroborating
    # only: a single-source likelihood prior cannot CONVICT alone (a real-but-rare browser must not be a
    # bot on rarity), so it is excluded from scoring.CONVICTING_CATEGORIES until the prior is corroborated
    # against a second (Tier-3 real-traffic) source.


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Signal(_Strict):
    """One observation from one layer at one moment."""

    schema_version: str = SCHEMA_VERSION
    session_id: str = Field(min_length=1, max_length=128)
    layer: Layer
    kind: str = Field(min_length=1, max_length=64)
    value: Any
    source: Source
    observed_at: datetime


class SignalGroups(_Strict):
    network: list[Signal] = Field(default_factory=list)
    browser: list[Signal] = Field(default_factory=list)
    behavioral: list[Signal] = Field(default_factory=list)
    reputation: list[Signal] = Field(default_factory=list)

    def of(self, layer: Layer) -> list[Signal]:
        return getattr(self, layer.value)  # type: ignore[no-any-return]


class Session(_Strict):
    """All signals sharing a ``session_id``, grouped by layer. The unit coherence runs over."""

    schema_version: str = SCHEMA_VERSION
    session_id: str = Field(min_length=1, max_length=128)
    remote_ip: str | None = None
    first_seen: datetime
    last_seen: datetime
    request_count: int = Field(ge=0)
    signals: SignalGroups = Field(default_factory=SignalGroups)

    def value(self, layer: Layer, kind: str) -> Any:
        """Resolve a single signal value by ``layer``/``kind``, or ``MISSING`` if absent."""
        for sig in self.signals.of(layer):
            if sig.kind == kind:
                return sig.value
        return MISSING


class Contradiction(_Strict):
    """One fired coherence rule, with the evidence that triggered it."""

    rule_id: str
    layers: list[Layer]
    detail: str
    weight: float = Field(ge=0.0, le=1.0)
    category: RuleCategory = RuleCategory.coherence
    evidence: list[str] = Field(default_factory=list)

    @property
    def is_cross_layer(self) -> bool:
        return len(set(self.layers)) >= 2


class LayerScores(_Strict):
    network: float = Field(ge=0.0, le=1.0, default=0.0)
    browser: float = Field(ge=0.0, le=1.0, default=0.0)
    behavioral: float = Field(ge=0.0, le=1.0, default=0.0)
    reputation: float = Field(ge=0.0, le=1.0, default=0.0)


class Verdict(_Strict):
    """The scored result for a session. Every point of bot-likelihood traces to its evidence."""

    schema_version: str = SCHEMA_VERSION
    session_id: str = Field(min_length=1, max_length=128)
    layer_scores: LayerScores
    contradictions: list[Contradiction] = Field(default_factory=list)
    incoherence_score: float = Field(ge=0.0, le=1.0)
    score: float = Field(ge=0.0, le=1.0)
    label: Label
    ruleset_version: str
    scored_at: datetime
