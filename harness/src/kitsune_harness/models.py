# harness/models — harness result models.
# ScenarioResult and the dated, reproducible Scoreboard.

"""Harness result models."""

from __future__ import annotations

from datetime import datetime

from kitsune_detector.models import Verdict
from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScenarioResult(_Strict):
    """One evader run scored by the detector."""

    scenario: str
    version: str
    verdict: Verdict


class Scoreboard(_Strict):
    """A dated, reproducible snapshot of evaders vs the detector.

    Carries the provenance needed to compare boards over time: the detector ruleset version and the
    generation timestamp travel with the data.
    """

    generated_at: datetime
    ruleset_version: str
    results: list[ScenarioResult] = Field(default_factory=list)
