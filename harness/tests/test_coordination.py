# tests/test_coordination — graded fleet verdicts via the TLS-identical-but-JS-divergent paradox.
# A real same-JA4 cohort is JS-homogeneous; an anti-detect fleet diverges JS yet shares one JA4.

from __future__ import annotations

from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Layer, Session, Signal, Source

from kitsune_harness.coordination import (
    render_coordination,
    score_cluster,
    score_corpus,
)

from .conftest import FIXED


def _sess(name: str, ja4: str | None, hw: int | None = None, plat: str | None = None) -> Session:
    sigs: list[Signal] = []
    if ja4 is not None:
        sigs.append(Signal(session_id=name, layer=Layer.network, kind="ja4", value=ja4, source=Source.edge, observed_at=FIXED))
    if hw is not None:
        sigs.append(Signal(session_id=name, layer=Layer.browser, kind="hardware_concurrency", value=hw, source=Source.collector, observed_at=FIXED))
    if plat is not None:
        sigs.append(Signal(session_id=name, layer=Layer.browser, kind="nav_platform_os", value=plat, source=Source.collector, observed_at=FIXED))
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


def test_render_coordination() -> None:
    assert "no JA4 cluster" in render_coordination([("solo", _sess("solo", "Z", 2))])
    md = render_coordination([("a", _sess("a", "X", 8)), ("b", _sess("b", "X", 32))])
    assert "fleet" in md and "score" in md and "cf" not in md
