# tests/test_fleet — tests for coordination / fleet clustering by low-level signature.
# Sessions sharing JA4 + hardware cluster; distinct ones don't.

from __future__ import annotations

from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Layer, Session, Signal, Source

from kitsune_harness.fleet import detect_fleets, fleet_signature, render_fleets

from .conftest import FIXED


def _sess(name: str, ja4: str, hw: int) -> Session:
    sigs = [
        Signal(session_id=name, layer=Layer.network, kind="ja4", value=ja4, source=Source.edge, observed_at=FIXED),
        Signal(session_id=name, layer=Layer.browser, kind="hardware_concurrency", value=hw, source=Source.collector, observed_at=FIXED),
    ]
    return group_signals(sigs)[0]


def test_signature_stable_across_fleet() -> None:
    assert fleet_signature(_sess("a", "X", 8)) == fleet_signature(_sess("b", "X", 8))
    assert fleet_signature(_sess("a", "X", 8)) != fleet_signature(_sess("c", "Y", 4))


def test_detect_fleets() -> None:
    corpus = [("a", _sess("a", "X", 8)), ("b", _sess("b", "X", 8)), ("c", _sess("c", "Y", 4))]
    fleets = detect_fleets(corpus)
    assert len(fleets) == 1
    assert next(iter(fleets.values())) == ["a", "b"]


def test_render() -> None:
    assert "no shared signatures" in render_fleets([("solo", _sess("solo", "Z", 2))])
    md = render_fleets([("a", _sess("a", "X", 8)), ("b", _sess("b", "X", 8))])
    assert "2 sessions share" in md and "a, b" in md
