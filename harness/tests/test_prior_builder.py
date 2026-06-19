# tests/test_prior_builder — the turnkey Tier-3 path: build the prevalence prior from real-captured fingerprints.
# Verifies build_prior_from_dir yields a prior whose schema matches the shipped (browserforge) one — model-loadable.

from __future__ import annotations

import json
from pathlib import Path

from kitsune_harness.browserforge_corpus import build_prior_from_dir, build_prior_from_sessions

_REPO = Path(__file__).resolve().parents[2]
_ENGINES = _REPO / "corpus" / "calibration" / "engines"
_SESSIONS = _REPO / "corpus" / "sessions"
_SHIPPED = _REPO / "detector" / "src" / "kitsune_detector" / "data" / "prevalence_prior.json"


def test_build_prior_from_dir_matches_shipped_schema(tmp_path: Path) -> None:
    # Build a prior from the real-captured engine fingerprints (stand-in for a Tier-3 real-traffic corpus).
    out = tmp_path / "prior.json"
    n = build_prior_from_dir(str(_ENGINES), str(out), source="test-real")
    built = json.loads(out.read_text())
    shipped = json.loads(_SHIPPED.read_text())

    assert n >= 1 and built["n"] == n
    assert built["source"] == "test-real"  # tags the independent source, not "browserforge"
    assert isinstance(built["threshold"], float)
    # Same top-level keys and same factor tables the detector's _load_prior consumes → drop-in replaceable.
    assert set(built) == set(shipped)
    assert set(built["prior"]) == set(shipped["prior"])


def test_build_prior_from_sessions_matches_shipped_schema(tmp_path: Path) -> None:
    # The real-traffic path: build the prior from SESSION JSONs (the collector+edge capture shape, what a
    # hosted-demo opt-in yields) using the detector's own features_from_session — so the prior is consistent
    # with scoring. (corpus/sessions are bot captures, used here only to exercise the BUILDER's shape.)
    out = tmp_path / "prior.json"
    n = build_prior_from_sessions(str(_SESSIONS), str(out), source="test-traffic")
    built = json.loads(out.read_text())
    shipped = json.loads(_SHIPPED.read_text())

    assert n >= 1 and built["n"] == n
    assert built["source"] == "test-traffic"
    assert isinstance(built["threshold"], float)
    assert set(built) == set(shipped)
    assert set(built["prior"]) == set(shipped["prior"])
