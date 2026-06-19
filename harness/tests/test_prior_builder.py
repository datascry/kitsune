# tests/test_prior_builder — the turnkey Tier-3 path: build the prevalence prior from real-captured fingerprints.
# Verifies build_prior_from_dir yields a prior whose schema matches the shipped (browserforge) one — model-loadable.

from __future__ import annotations

import json
from pathlib import Path

from kitsune_harness.browserforge_corpus import build_prior_from_dir

_REPO = Path(__file__).resolve().parents[2]
_ENGINES = _REPO / "corpus" / "calibration" / "engines"
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
