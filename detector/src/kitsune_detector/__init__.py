# detector — session-correlated, cross-layer incoherence scoring (package root).
# Re-exports the public models and the Detector facade.

"""Kitsune detector — session-correlated, cross-layer incoherence scoring."""

from __future__ import annotations

from .config import SCHEMA_VERSION
from .detector import Detector
from .models import (
    Contradiction,
    Label,
    Layer,
    LayerScores,
    Session,
    Signal,
    SignalGroups,
    Source,
    Verdict,
)

__version__ = "0.1.0"

__all__ = [
    "SCHEMA_VERSION",
    "Contradiction",
    "Detector",
    "Label",
    "Layer",
    "LayerScores",
    "Session",
    "Signal",
    "SignalGroups",
    "Source",
    "Verdict",
    "__version__",
]
