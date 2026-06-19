# tests/test_prior_builder — the turnkey Tier-3 path: build the prevalence prior from real-captured fingerprints.
# Verifies build_prior_from_dir yields a prior whose schema matches the shipped (browserforge) one — model-loadable.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kitsune_harness.browserforge_corpus import build_prior_from_dir, build_prior_from_sessions, write_prior

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


def _feat(plat: str, gpu: str, screen: str, cores: str) -> dict[str, Any]:
    return {"plat": plat, "gpu": gpu, "screen": screen, "cores": cores, "color": 24}


def test_threshold_is_cross_source_conservative(tmp_path: Path) -> None:
    # The v0.74.24 FP fix: a SELF-referential p1 over-flags an independent dataset, so write_prior takes an
    # independent threshold_feats and uses the CONSERVATIVE (deeper) bound min(self-p1, independent-p1).
    # Base set: 200 of one common joint → its own p1 is shallow (the common joint scores high).
    feats = [_feat("Windows", "intel", "small-land", "5-8") for _ in range(200)]
    # Independent set: mostly the same common joint, but 5% a joint RARE in the prior (nvidia/large-port/17+)
    # → its p1 sits deep in the prior's tail.
    independent = [_feat("Windows", "intel", "small-land", "5-8") for _ in range(95)]
    independent += [_feat("Windows", "nvidia", "large-port", "17+") for _ in range(5)]

    self_t = write_prior(feats, str(tmp_path / "self.json"), "browserforge")
    cross_t = write_prior(feats, str(tmp_path / "cross.json"), "browserforge", threshold_feats=independent)

    # The cross-source threshold must be at least as DEEP (<=) as the self-p1 — never shallower (FP-safe).
    assert cross_t <= self_t
    # And here strictly deeper, because the independent set has a rarer joint in the prior's tail.
    assert cross_t < self_t
    # Metadata records which calibration was used (so a stale prior is auditable).
    assert json.loads((tmp_path / "self.json").read_text())["threshold_calibration"] == "self-p1"
    assert json.loads((tmp_path / "cross.json").read_text())["threshold_calibration"] == "cross-source-conservative"
