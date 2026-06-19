# tests/test_prevalence_mirror — lock the turnkey prevalence pipeline: harness BUILDS the prior, detector SCORES it.
# The two prevalence modules are duplicated mirrors; if they drift, a built prior would score differently than intended.

from __future__ import annotations

import json
from pathlib import Path

import kitsune_detector.prevalence as dp

import kitsune_harness.prevalence as hp
from kitsune_harness.prevalence import build_prior, features_from_fingerprint

_ENGINES = Path(__file__).resolve().parents[2] / "corpus" / "calibration" / "engines"


def test_prevalence_factors_are_mirrored() -> None:
    # The structural invariant both the builder (harness) and the scorer (detector) iterate. If one side's
    # _FACTORS is edited without the other, a harness-built prior would be scored against the wrong factors.
    assert hp._FACTORS == dp._FACTORS


def test_harness_built_prior_scores_identically_in_the_detector() -> None:
    # Build a prior the harness way (what `build_prior_from_dir`/`--build-prior-from-sessions` do), then assert
    # the DETECTOR's log_prevalence returns bit-identical scores to the harness's on it. This is the turnkey
    # pipeline's correctness invariant: an operator's real-traffic prior must score in the detector exactly as
    # the builder intends — a silent mirror drift would make the second-source prior subtly wrong.
    fingerprints = [json.loads(p.read_text()) for p in sorted(_ENGINES.glob("*.json"))]
    feats = [features_from_fingerprint(fp) for fp in fingerprints]
    prior = build_prior(feats)
    # The training vectors plus a clearly-improbable joint (Windows UA + Apple GPU) — exercise both the
    # in-distribution and the deep-tail paths through log_prevalence.
    probes = [*feats, {"plat": "Windows", "gpu": "apple", "screen": "laptop-land", "color": 30, "cores": "5-8"}]
    for features in probes:
        assert hp.log_prevalence(features, prior) == dp.log_prevalence(features, prior), features


# --- Feature-EXTRACTION mirrors: the builder's --build-prior-from-dir path extracts features harness-side,
# but the detector extracts them at scoring time. The bucketing helpers are duplicated (and screen even
# differs in signature), so a drift would silently mis-bucket a fp-dict-built prior vs the detector's scoring.


def test_cores_bucket_mirrors() -> None:
    for n in [None, 0, 1, 2, 3, 4, 5, 8, 12, 16, 17, 32, 64, 128, "x"]:
        assert hp.cores_bucket(n) == dp._cores_bucket(n), n


def test_screen_bucket_mirrors() -> None:
    # harness takes (w, h); detector takes the "WxH" string — equivalent inputs must bucket identically.
    for w, h in [(1920, 1080), (1470, 956), (390, 844), (3840, 2160), (1280, 720), (0, 0), (2560, 1440)]:
        assert hp.screen_bucket(w, h) == dp._screen_bucket(f"{w}x{h}"), (w, h)


def test_gpu_family_mirrors() -> None:
    # harness inlines the gpu family in features_from_fingerprint; assert it matches detector._gpu_family.
    renderers = [
        "ANGLE (NVIDIA, GeForce RTX 3080)",
        "ANGLE (Apple, Apple M2)",
        "ANGLE (Intel, Intel UHD Graphics)",
        "ANGLE (AMD, Radeon)",
        "Adreno (TM) 640",
        "ANGLE (Google, SwiftShader)",
        "Some Unknown GPU",
    ]
    for renderer in renderers:
        harness_gpu = features_from_fingerprint({"videoCard": {"renderer": renderer}})["gpu"]
        assert harness_gpu == dp._gpu_family(renderer), renderer
