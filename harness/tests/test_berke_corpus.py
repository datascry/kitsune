# tests/test_berke_corpus — the Berke (PoPETs 2025) CSV → prevalence-prior adapter.
# Offline: synthetic rows in the published data-dictionary schema; pins row mapping, screen parsing, prior build.

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from kitsune_harness.berke_corpus import (
    COL_COLOR,
    COL_CORES,
    COL_RENDERER,
    COL_SCREEN,
    COL_UA,
    build_prior_from_berke,
    features_from_berke_csv,
    fingerprint_from_berke_row,
    parse_screen,
)
from kitsune_harness.prevalence import features_from_fingerprint, log_prevalence

_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
_MAC = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.0 Safari/605.1.15"
)


def _row(ua: str, screen: str, cores: str, renderer: str, color: str = "24") -> dict[str, str]:
    return {COL_UA: ua, COL_SCREEN: screen, COL_CORES: cores, COL_RENDERER: renderer, COL_COLOR: color}


def test_parse_screen_handles_bracket_pair_and_garbage() -> None:
    assert parse_screen("[1920,1080]") == (1920, 1080)
    assert parse_screen("1470x956") == (1470, 956)  # WxH accepted defensively
    assert parse_screen("") == (0, 0)
    assert parse_screen("n/a") == (0, 0)
    assert parse_screen("1080") == (0, 0)  # single number → unscored


def test_row_maps_to_detector_feature_shape() -> None:
    # The mapped row must extract the SAME features the detector's features_from_fingerprint produces — the
    # whole point of reusing that extractor (UA-derived plat, renderer→gpu family, bucketed screen/cores).
    fp = fingerprint_from_berke_row(_row(_MAC, "[1470,956]", "8", "Apple GPU"))
    feats = features_from_fingerprint(fp)
    assert feats == {"plat": "macOS", "gpu": "apple", "screen": "laptop-land", "color": "24", "cores": "5-8"}


def test_features_from_csv_reads_all_rows(tmp_path: Path) -> None:
    p = tmp_path / "berke.csv"
    rows = [
        _row(_WIN, "[1920,1080]", "8", "ANGLE (Intel, Intel UHD Graphics)"),
        _row(_MAC, "[1470,956]", "10", "Apple GPU"),
    ]
    with p.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    feats = features_from_berke_csv(str(p))
    assert len(feats) == 2
    assert {f["plat"] for f in feats} == {"Windows", "macOS"}


def test_missing_browser_attributes_column_fails_loud(tmp_path: Path) -> None:
    # The survey-experiment-data.csv variant lacks browser attributes — building a prior from it is a usage
    # error, not a silent empty prior. The adapter names the wrong-file case.
    p = tmp_path / "survey-only.csv"
    with p.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["ResponseId", "showdata"])
        w.writeheader()
        w.writerow({"ResponseId": "R1", "showdata": "true"})
    with pytest.raises(SystemExit, match=COL_UA):
        features_from_berke_csv(str(p))


def test_empty_csv_fails_loud(tmp_path: Path) -> None:
    p = tmp_path / "empty.csv"
    p.write_text(f"{COL_UA},{COL_SCREEN}\n")  # header only, no rows
    with pytest.raises(SystemExit, match="no rows"):
        features_from_berke_csv(str(p))


def test_build_prior_writes_aggregate_only_and_orders_by_probability(tmp_path: Path) -> None:
    # A real-traffic-shaped prior: many common Windows/Intel laptops + one rare Windows/Apple-GPU combo. The
    # output is the aggregate prior (tables + threshold), NO rows; the common combo scores above the rare one.
    csv_path = tmp_path / "berke.csv"
    rows = [_row(_WIN, "[1920,1080]", "8", "ANGLE (Intel, Intel UHD Graphics)") for _ in range(50)]
    rows.append(_row(_WIN, "[1470,956]", "8", "Apple GPU"))  # Windows UA + Apple GPU = improbable joint
    with csv_path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    out = tmp_path / "prior.json"
    n = build_prior_from_berke(str(csv_path), str(out))
    assert n == 51
    doc = json.loads(out.read_text())
    assert doc["source"] == "berke-popets2025"
    assert set(doc.keys()) == {"n", "source", "threshold", "threshold_calibration", "prior"}  # aggregate only
    # The common combo is more probable than the rare one under the freshly built real-traffic prior.
    common_row = _row(_WIN, "[1920,1080]", "8", "ANGLE (Intel, Intel UHD Graphics)")
    common = features_from_fingerprint(fingerprint_from_berke_row(common_row))
    rare = features_from_fingerprint(fingerprint_from_berke_row(_row(_WIN, "[1470,956]", "8", "Apple GPU")))
    assert log_prevalence(common, doc["prior"]) > log_prevalence(rare, doc["prior"])
