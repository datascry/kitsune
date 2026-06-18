# tests/test_fleet — tests for coordination / fleet clustering by low-level signature.
# Sessions sharing JA4 + hardware cluster; distinct ones don't.

from __future__ import annotations

from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Layer, Session, Signal, Source

from kitsune_harness.fleet import detect_fleets, fleet_signature, render_fleets

from .conftest import FIXED


def _mk(name: str, layer: Layer, kind: str, value: object, src: Source) -> Signal:
    return Signal(session_id=name, layer=layer, kind=kind, value=value, source=src, observed_at=FIXED)


def _sess(name: str, ja4: str, hw: int) -> Session:
    sigs = [
        _mk(name, Layer.network, "ja4", ja4, Source.edge),
        _mk(name, Layer.browser, "hardware_concurrency", hw, Source.collector),
    ]
    return group_signals(sigs)[0]


def test_signature_ignores_randomized_js_traits() -> None:
    # Same JA4, DIFFERENT hardware (the Camoufox case) must still share a signature.
    assert fleet_signature(_sess("a", "X", 8)) == fleet_signature(_sess("b", "X", 32))
    assert fleet_signature(_sess("a", "X", 8)) != fleet_signature(_sess("c", "Y", 4))


def test_signature_keys_on_cipher_prefix_not_randomized_ja4c() -> None:
    # Same cipher-suite prefix, DIFFERENT JA4_c (Camoufox per-launch TLS randomization) → same sig.
    assert fleet_signature(_sess("a", "t13d_aaaa_1111", 8)) == fleet_signature(_sess("b", "t13d_aaaa_2222", 8))


def test_signature_missing_ja4() -> None:
    sess = group_signals([_mk("x", Layer.browser, "hardware_concurrency", 8, Source.collector)])[0]
    assert fleet_signature(sess) == "ja4=?"


def test_detect_fleets() -> None:
    # a, b: same JA4, randomized hardware → one fleet. c: different JA4 → alone.
    corpus = [("a", _sess("a", "X", 8)), ("b", _sess("b", "X", 32)), ("c", _sess("c", "Y", 4))]
    fleets = detect_fleets(corpus)
    assert len(fleets) == 1
    assert next(iter(fleets.values())) == ["a", "b"]


def test_render() -> None:
    assert "no shared signatures" in render_fleets([("solo", _sess("solo", "Z", 2))])
    md = render_fleets([("a", _sess("a", "X", 8)), ("b", _sess("b", "X", 8))])
    assert "2 sessions share" in md and "a, b" in md
