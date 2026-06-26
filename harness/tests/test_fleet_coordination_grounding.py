# tests/test_fleet_coordination_grounding — the LIVE-served fleet corpus, regraded by the coordination scorer.
# Frozen from a real detector /ingest -> /session capture; the two collision arms convict, the paradox caps.

from __future__ import annotations

import json
from pathlib import Path

from kitsune_detector.models import Session

from kitsune_harness.coordination import score_corpus

_CORPUS = Path(__file__).resolve().parents[2] / "corpus" / "fleet-live"


def _load(*names: str) -> list[tuple[str, Session]]:
    return [(n, Session.model_validate(json.loads((_CORPUS / f"{n}.json").read_text()))) for n in names]


def test_live_served_fleet_convicts_both_collision_arms_and_caps_paradox() -> None:
    # The fleet was POSTed through a real detector's /ingest, correlated + stored, then served back over
    # /session — these fixtures are that real-served output (see harness/tools/fleet_coordination_demo.py).
    # Grading them proves the end-to-end coordination path; the conviction gate is exercised three ways.
    corpus = _load(
        "fleet-clone-0",
        "fleet-clone-1",
        "fleet-clone-2",
        "fleet-trace-0",
        "fleet-trace-1",
        "fleet-trace-2",
        "paradox-ctl-0",
        "paradox-ctl-1",
    )
    verdicts = score_corpus(corpus)
    clone = next(v for v in verdicts if "fleet-clone-0" in v.members)
    trace = next(v for v in verdicts if "fleet-trace-0" in v.members)
    paradox = next(v for v in verdicts if "paradox-ctl-0" in v.members)

    # fp-collision arm: one cloned high-entropy fingerprint across distinct IPs + an automation tell -> fleet.
    assert clone.label == "fleet" and clone.cloned_fingerprint == "9f2c7b41a0e8d35c"
    # trace-collision arm: one replayed pointer trace across distinct IPs (unambiguous) -> fleet.
    assert trace.label == "fleet" and trace.cloned_trace == "7ab3e9f15c2d8061"
    # paradox-only control: JS divergence under one JA4 from ONE IP, no convicting signal -> candidate, not
    # fleet. A real diverse cohort on one browser build produces this shape, so the gate must NOT convict it.
    assert paradox.label == "candidate"
