# harness — run evaders against the detector, emit reproducible scoreboards (package).
# Re-exports Harness, Scoreboard, scenarios, renderers, and the ethics allow-list.

"""Kitsune harness — run evaders against the detector, emit reproducible scoreboards."""

from __future__ import annotations

from .allowlist import EthicsError, assert_allowed, is_allowed
from .harness import Harness
from .models import ScenarioResult, Scoreboard
from .scenarios import ReplayScenario, Scenario
from .scoreboard import render_json, render_markdown

__version__ = "0.1.0"

__all__ = [
    "EthicsError",
    "Harness",
    "ReplayScenario",
    "Scenario",
    "ScenarioResult",
    "Scoreboard",
    "__version__",
    "assert_allowed",
    "is_allowed",
    "render_json",
    "render_markdown",
]
