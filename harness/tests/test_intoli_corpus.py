# harness/tests/test_intoli_corpus — the Intoli real-traffic mapper (second calibration source).
# Pins the mapper output and the mobile false-positive the dataset surfaced.

from __future__ import annotations

from datetime import UTC, datetime

from kitsune_detector.detector import Detector
from kitsune_detector.ingest import group_signals

from kitsune_harness.intoli_corpus import intoli_signals

NOW = datetime(2026, 6, 19, tzinfo=UTC)

# A real Android record from the dataset: the UA says Android, navigator.platform is Linux — legitimate.
_ANDROID = {
    "userAgent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",  # noqa: E501
    "platform": "Linux armv8l",
    "vendor": "Google Inc.",
    "language": "en-US",
    "screenWidth": 412,
    "screenHeight": 915,
}
_DESKTOP = {
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",  # noqa: E501
    "platform": "Win32",
    "vendor": "Google Inc.",
    "language": "en-US",
    "screenWidth": 1920,
    "screenHeight": 1080,
}


def test_mapper_emits_only_supported_signals() -> None:
    sigs = intoli_signals(_ANDROID, "a", NOW)
    kinds = {s.kind for s in sigs}
    # only coherence inputs the dataset genuinely supports — never absence-based environment tells
    assert kinds == {
        "ua_platform",
        "ua_engine",
        "nav_platform_os",
        "vendor_engine",
        "nav_language_primary",
        "screen_resolution",
    }
    assert "media_devices_empty" not in kinds and "no_plugins" not in kinds


def test_real_android_mismatch_is_the_root_cause() -> None:
    # The second source surfaced that a legitimate Android browser carries UA-platform `Android` but a
    # `Linux` navigator.platform — the desktop-oriented platform-coherence rules read that as a
    # contradiction (a 73% FP on real mobile traffic). This pins the root-cause signal pair; the fix is
    # per-platform OS-family normalization (Android is a Linux-family OS) handled in the per-browser work.
    sigs = {s.kind: s.value for s in intoli_signals(_ANDROID, "a", NOW)}
    assert sigs["ua_platform"] == "Android"
    assert sigs["nav_platform_os"] == "Linux"


def test_real_desktop_is_clean() -> None:
    verdict = Detector().score(group_signals(intoli_signals(_DESKTOP, "d", NOW))[0])
    assert verdict.label.value == "human"
