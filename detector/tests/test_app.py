# tests/test_app — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from kitsune_detector.app import create_app
from kitsune_detector.detector import Detector
from kitsune_detector.store import Store

from .conftest import load_example


@pytest.fixture
def client(fixed_clock) -> TestClient:
    app = create_app(detector=Detector(clock=fixed_clock), store=Store(":memory:"))
    return TestClient(app)


def _signals_from(example: str) -> list[dict]:
    session = load_example(example)
    flat: list[dict] = []
    for layer_signals in session["signals"].values():  # type: ignore[union-attr]
        flat.extend(layer_signals)
    return flat


def test_healthz(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_ingest_then_fetch(client: TestClient) -> None:
    payload = _signals_from("session_bot.json")
    resp = client.post("/ingest", json=payload)
    assert resp.status_code == 200
    verdicts = resp.json()
    assert verdicts[0]["label"] == "bot"

    fetched = client.get("/verdict/bot-001")
    assert fetched.status_code == 200
    assert fetched.json()["session_id"] == "bot-001"

    board = client.get("/scoreboard")
    assert board.status_code == 200
    assert len(board.json()) == 1


def test_verdict_404(client: TestClient) -> None:
    assert client.get("/verdict/nope").status_code == 404


def test_create_app_defaults() -> None:
    # exercise the default Detector()/Store() construction branch
    client = TestClient(create_app())
    assert client.get("/healthz").status_code == 200


def test_index_serves_collector(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert "navigator.webdriver" in resp.text
    assert "/ingest" in resp.text
