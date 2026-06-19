# detector/tests/test_prevalence — the likelihood model scores improbable joints and gates safely.
# A common fingerprint clears; a coherent-but-rare combination is deep in the prior's tail and fires.

from __future__ import annotations

from datetime import UTC, datetime

from kitsune_detector import prevalence
from kitsune_detector.detector import Detector
from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Layer, Session, Signal, Source

NOW = datetime(2026, 6, 19, tzinfo=UTC)


def _session(**fields: object) -> Session:
    sigs = [
        Signal(session_id="s", layer=Layer.browser, kind=k, value=v, source=Source.collector, observed_at=NOW)
        for k, v in fields.items()
        if v is not None
    ]
    return group_signals(sigs)[0]


def _fp(plat: str | None, renderer: str, screen: str, color: int, cores: int) -> Session:
    return _session(
        ua_platform=plat,
        webgl_renderer=renderer,
        screen_resolution=screen,
        color_depth=color,
        hardware_concurrency=cores,
    )


def test_gpu_family_branches() -> None:
    f = prevalence._gpu_family
    assert f("ANGLE (NVIDIA, GeForce RTX 3080)") == "nvidia"
    assert f("ANGLE (Apple, Apple M2)") == "apple"
    assert f("ANGLE (Intel, Intel UHD Graphics)") == "intel"
    assert f("ANGLE (AMD, Radeon)") == "amd"
    assert f("Adreno (TM) 640") == "mobile"
    assert f("ANGLE (Google, SwiftShader)") == "swiftshader"
    assert f("Some Unknown GPU") == "other"


def test_features_from_session() -> None:
    feats = prevalence.features_from_session(_fp("macOS", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8))
    assert feats == {"plat": "macOS", "gpu": "apple", "screen": "1470x956", "color": 30, "cores": 8}


def test_common_clears_improbable_fires() -> None:
    # a common real macOS/Apple combo is not improbable
    assert prevalence.is_improbable(_fp("macOS", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8)) is False
    # coherent fields, improbable joint: a Windows UA with an Apple GPU + a Mac screen — no real user
    assert prevalence.is_improbable(_fp("Windows", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8)) is True


def test_unscoreable_sessions_never_fire() -> None:
    # missing platform/gpu → cannot score → never fire (a non-browser / no-JS session)
    assert prevalence.is_improbable(_fp(None, "ANGLE (Apple, Apple M2)", "1470x956", 30, 8)) is False
    assert prevalence.is_improbable(_fp("?", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8)) is False
    assert prevalence.is_improbable(_session(ua_platform="Windows")) is False  # no webgl_renderer


def test_log_prevalence_orders_by_probability() -> None:
    p = prevalence._load_prior()["prior"]
    common = prevalence.features_from_session(_fp("macOS", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8))
    rare = prevalence.features_from_session(_fp("Windows", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8))
    assert prevalence.log_prevalence(common, p) > prevalence.log_prevalence(rare, p)


def test_detector_emits_prevalence_low_and_rule_fires() -> None:
    verdict = Detector().score(_fp("Windows", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8))
    assert "br.fingerprint_improbable" in {c.rule_id for c in verdict.contradictions}
    # a common fingerprint does not trip it
    clear = Detector().score(_fp("macOS", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8))
    assert "br.fingerprint_improbable" not in {c.rule_id for c in clear.contradictions}
