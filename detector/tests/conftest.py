# tests/conftest — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime

import pytest

from kitsune_detector import contracts
from kitsune_detector.detector import Detector
from kitsune_detector.models import Layer, Session, Signal, Source

FIXED = datetime(2026, 6, 17, 12, 0, 0, tzinfo=UTC)


def make_signal(
    session_id: str,
    layer: Layer,
    kind: str,
    value: object,
    *,
    source: Source = Source.collector,
    at: datetime = FIXED,
) -> Signal:
    return Signal(session_id=session_id, layer=layer, kind=kind, value=value, source=source, observed_at=at)


def load_example(name: str) -> dict[str, object]:
    return json.loads((contracts.contracts_dir() / "examples" / name).read_text())


@pytest.fixture
def fixed_clock() -> Callable[[], datetime]:
    return lambda: FIXED


@pytest.fixture
def detector(fixed_clock: Callable[[], datetime]) -> Detector:
    return Detector(clock=fixed_clock)


@pytest.fixture
def human_session() -> Session:
    return Session.model_validate(load_example("session_human.json"))


@pytest.fixture
def bot_session() -> Session:
    return Session.model_validate(load_example("session_bot.json"))


@pytest.fixture(autouse=True)
def _clear_contract_caches():
    """Keep contract-loader caches from leaking env overrides between tests."""
    yield
    contracts.contracts_dir.cache_clear()
    contracts.load_schema.cache_clear()
    contracts._registry.cache_clear()
    contracts._validator.cache_clear()
