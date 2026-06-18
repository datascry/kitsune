# tests/test_coordination — graded fleet verdicts via the TLS-identical-but-JS-divergent paradox.
# A real same-JA4 cohort is JS-homogeneous; an anti-detect fleet diverges JS yet shares one JA4.

from __future__ import annotations

from datetime import timedelta

from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Layer, Session, Signal, Source

from kitsune_harness.coordination import (
    render_coordination,
    score_cluster,
    score_corpus,
)

from .conftest import FIXED


def _sess(
    name: str, ja4: str | None, hw: int | None = None, plat: str | None = None, *, offset_s: float = 0.0
) -> Session:
    when = FIXED + timedelta(seconds=offset_s)

    def mk(layer: Layer, kind: str, value: object, src: Source) -> Signal:
        return Signal(session_id=name, layer=layer, kind=kind, value=value, source=src, observed_at=when)

    sigs: list[Signal] = []
    if ja4 is not None:
        sigs.append(mk(Layer.network, "ja4", ja4, Source.edge))
    if hw is not None:
        sigs.append(mk(Layer.browser, "hardware_concurrency", hw, Source.collector))
    if plat is not None:
        sigs.append(mk(Layer.browser, "nav_platform_os", plat, Source.collector))
    return group_signals(sigs)[0]


def test_paradox_is_a_fleet() -> None:
    # Same JA4, divergent JS (the Camoufox shape) → high score, labeled "fleet".
    members = [("a", _sess("a", "X", 8)), ("b", _sess("b", "X", 32)), ("c", _sess("c", "X", 8))]
    v = score_cluster("X", members)
    assert v.label == "fleet"
    assert v.score >= 0.60
    assert v.diverged_traits == {"hardware_concurrency": 2}
    assert any("divergent" in e for e in v.evidence)


def test_homogeneous_cluster_is_only_a_candidate() -> None:
    # Same JA4 AND identical JS — looks like a real same-build cohort, not a spoofing fleet.
    members = [("a", _sess("a", "X", 8, "Windows")), ("b", _sess("b", "X", 8, "Windows"))]
    v = score_cluster("X", members)
    assert v.label == "candidate"
    assert v.diverged_traits == {}
    assert any("homogeneous" in e for e in v.evidence)


def test_larger_fleet_scores_higher() -> None:
    small = score_cluster("X", [("a", _sess("a", "X", 8)), ("b", _sess("b", "X", 32))])
    big = score_cluster("X", [(n, _sess(n, "X", hw)) for n, hw in [("a", 8), ("b", 32), ("c", 16), ("d", 4)]])
    assert big.score > small.score


def test_score_corpus_clusters_and_sorts() -> None:
    corpus = [
        ("cf1", _sess("cf1", "X", 8)),
        ("cf2", _sess("cf2", "X", 32)),  # paradox fleet
        ("solo", _sess("solo", "Y", 4)),  # alone → not graded
        ("noja4", _sess("noja4", None, 4)),  # no JA4 → skipped
    ]
    verdicts = score_corpus(corpus)
    assert len(verdicts) == 1
    assert verdicts[0].members == ["cf1", "cf2"]
    assert verdicts[0].label == "fleet"


def test_timing_lockstep_adds_confidence() -> None:
    # Same JA4 + same JS, but tight vs spread arrival → lockstep raises the score.
    tight = score_cluster("X", [("a", _sess("a", "X", 8, offset_s=0)), ("b", _sess("b", "X", 8, offset_s=30))])
    spread = score_cluster("X", [("a", _sess("a", "X", 8, offset_s=0)), ("b", _sess("b", "X", 8, offset_s=9999))])
    assert tight.score > spread.score
    assert tight.span_seconds == 30.0
    assert any("lockstep" in e for e in tight.evidence)
    assert any("no lockstep" in e for e in spread.evidence)


def test_ja4c_randomization_is_a_fleet() -> None:
    # Shared cipher-suite prefix, homogeneous JS, but DIFFERENT JA4_c (extensions) per launch — the
    # Camoufox TLS-randomization shape. Clusters by prefix and the JA4_c divergence makes it a fleet.
    members = [
        ("a", _sess("a", "t13d_aaaa_1111", 8, "Windows")),
        ("b", _sess("b", "t13d_aaaa_2222", 8, "Windows")),
        ("c", _sess("c", "t13d_aaaa_3333", 8, "Windows")),
    ]
    v = score_corpus([(n, s) for n, s in members])[0]
    assert v.ja4 == "t13d_aaaa"  # keyed on the stable prefix, not the randomized full JA4
    assert v.ja4c_divergent is True
    assert v.diverged_traits == {}  # JS is homogeneous — the catch is purely the TLS randomization
    assert v.label == "fleet"
    assert any("extensions/sig-algs divergent" in e for e in v.evidence)


def test_shared_full_ja4_not_divergent() -> None:
    # Members sharing the *full* JA4 (real same-build cohort) → no JA4_c divergence flag.
    v = score_cluster("p", [("a", _sess("a", "p_q_r", 8, "Windows")), ("b", _sess("b", "p_q_r", 8, "Windows"))])
    assert v.ja4c_divergent is False


def test_single_member_cluster_has_no_span() -> None:
    # Defensive: score_cluster with one member yields no timing span and no lockstep evidence.
    v = score_cluster("X", [("solo", _sess("solo", "X", 8))])
    assert v.span_seconds is None
    assert not any("lockstep" in e for e in v.evidence)


def test_render_coordination() -> None:
    assert "no JA4 cluster" in render_coordination([("solo", _sess("solo", "Z", 2))])
    md = render_coordination([("a", _sess("a", "X", 8)), ("b", _sess("b", "X", 32))])
    assert "fleet" in md and "score" in md and "cf" not in md
