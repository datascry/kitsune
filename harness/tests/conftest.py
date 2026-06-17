# tests/conftest — harness test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from kitsune_detector.contracts import contracts_dir
from kitsune_detector.detector import Detector
from kitsune_detector.models import Signal

from kitsune_harness.scenarios import ReplayScenario

FIXED = datetime(2026, 6, 17, 12, 0, 0, tzinfo=UTC)


class FakeScenario:
    """A scenario returning a fixed signal list (no file, no browser)."""

    def __init__(self, name: str, version: str, signals: list[Signal]) -> None:
        self.name = name
        self.version = version
        self._signals = signals

    def collect(self) -> list[Signal]:
        return self._signals


@pytest.fixture
def fixed_clock() -> Callable[[], datetime]:
    return lambda: FIXED


@pytest.fixture
def detector(fixed_clock: Callable[[], datetime]) -> Detector:
    return Detector(clock=fixed_clock)


@pytest.fixture
def examples() -> Path:
    return contracts_dir() / "examples"


@pytest.fixture
def human_scenario(examples: Path) -> ReplayScenario:
    return ReplayScenario("vanilla", "0.1.0", examples / "session_human.json")


@pytest.fixture
def bot_scenario(examples: Path) -> ReplayScenario:
    return ReplayScenario("naive-bot", "0.1.0", examples / "session_bot.json")
