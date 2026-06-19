# harness/tests/test_prevalence — the likelihood model separates probable from improbable joints.
# A coherent-but-rare field combination scores far below a common one under the prior.

from __future__ import annotations

from kitsune_harness.prevalence import (
    build_prior,
    features_from_fingerprint,
    log_prevalence,
    screen_bucket,
)


def test_screen_bucket() -> None:
    assert screen_bucket(1920, 1080) == "desktop-land"
    assert screen_bucket(1470, 956) == "laptop-land"
    assert screen_bucket(390, 844) == "mobile-port"
    assert screen_bucket(3840, 2160) == "large-land"
    assert screen_bucket(1366, 768) == "small-land"
    assert screen_bucket(0, 0) is None and screen_bucket(-1, 5) is None


def _fp(ua: str, renderer: str, w: int, h: int, color: int, cores: int) -> dict:
    return {
        "navigator": {"userAgent": ua, "hardwareConcurrency": cores},
        "screen": {"width": w, "height": h, "colorDepth": color},
        "videoCard": {"renderer": renderer},
    }


WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/147"
MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/147"


def test_features_extraction() -> None:
    f = features_from_fingerprint(_fp(WIN, "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11)", 1920, 1080, 24, 16))
    assert f == {"plat": "Windows", "gpu": "nvidia", "screen": "desktop-land", "color": 24, "cores": 16}
    g = features_from_fingerprint(_fp(MAC, "ANGLE (Apple, ANGLE Metal Renderer: Apple M2)", 1470, 956, 30, 8))
    assert g["plat"] == "macOS" and g["gpu"] == "apple"


def test_prior_separates_probable_from_improbable() -> None:
    # Build a prior where Windows machines have Intel/NVIDIA GPUs at 1920x1080, Macs have Apple GPUs.
    feats = []
    for _ in range(200):
        feats.append(features_from_fingerprint(_fp(WIN, "ANGLE (Intel, Intel UHD Graphics)", 1920, 1080, 24, 8)))
    for _ in range(50):
        feats.append(features_from_fingerprint(_fp(WIN, "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080)", 1920, 1080, 24, 16)))
    for _ in range(200):
        feats.append(features_from_fingerprint(_fp(MAC, "ANGLE (Apple, Apple M2)", 1470, 956, 30, 8)))
    prior = build_prior(feats)

    probable = features_from_fingerprint(_fp(WIN, "ANGLE (Intel, Intel UHD Graphics)", 1920, 1080, 24, 8))
    # coherent fields, IMPROBABLE joint: a Windows UA with an Apple GPU + a Mac-only screen — no real user
    improbable = features_from_fingerprint(_fp(WIN, "ANGLE (Apple, Apple M2)", 1470, 956, 30, 8))

    assert log_prevalence(probable, prior) > log_prevalence(improbable, prior)
    # the improbable one is deep in the tail
    assert log_prevalence(improbable, prior) < -10


def test_prior_structure() -> None:
    prior = build_prior([features_from_fingerprint(_fp(WIN, "Intel UHD", 1920, 1080, 24, 8))])
    assert prior["gpu"]["Windows"]["intel"] == 1.0
    assert prior["cores"]["_"]["8"] == 1.0
