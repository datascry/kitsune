# harness/scenarios — evader scenarios.
# Scenario protocol + ReplayScenario (deterministic replay of a recorded session).

"""Evader scenarios.

A scenario is anything that produces a session's worth of signals to score. Real evaders (stealth,
agent, go-tls) live under ``evaders/`` and drive a browser/TLS client through the edge; for the
spine and for deterministic tests, ``ReplayScenario`` replays a recorded session fixture — no
browser, no network, fully reproducible.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol, runtime_checkable

from kitsune_detector.models import Session, Signal


@runtime_checkable
class Scenario(Protocol):
    """Produces the signals for one session."""

    name: str
    version: str

    def collect(self) -> list[Signal]: ...


class ReplayScenario:
    """Replays the signals from a recorded ``Session`` fixture (JSON on disk)."""

    def __init__(self, name: str, version: str, session_path: str | Path) -> None:
        self.name = name
        self.version = version
        self._session_path = Path(session_path)

    def collect(self) -> list[Signal]:
        session = Session.model_validate(json.loads(self._session_path.read_text()))
        groups = session.signals
        return [*groups.network, *groups.browser, *groups.behavioral, *groups.reputation]
