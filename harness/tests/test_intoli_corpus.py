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
# A real Chrome-on-iOS record (CriOS): Apple forces WebKit so the UA carries the Safari token (ua_engine
# "safari") while navigator.vendor follows the BRAND → "Google Inc." (vendor_engine "chromium"). The two
# axes disagree legitimately — this is the real-traffic combination that convicted iOS users on
# br.vendor_vs_ua (107/10000) until v0.74.22.
_IOS_CHROME = {
    "userAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/123.0.6312.52 Mobile/15E148 Safari/604.1",  # noqa: E501
    "vendor": "Google Inc.",
    "language": "en-US",
    "screenWidth": 393,
    "screenHeight": 852,
}


def test_mapper_emits_only_faithfully_paired_signals() -> None:
    sigs = intoli_signals(_ANDROID, "a", NOW)
    kinds = {s.kind for s in sigs}
    # Only the fields verified to track the device: UA / vendor / language / screen. navigator.platform
    # is omitted (70% of dataset records report "Linux x86_64" regardless of device — see module docstring),
    # and absence-based environment tells are omitted (missing from the dataset, not the real browser).
    assert kinds == {
        "ua_platform",
        "ua_engine",
        "vendor_engine",
        "nav_language_primary",
        "screen_resolution",
    }
    assert "nav_platform_os" not in kinds  # the unreliable field is not derived
    assert "media_devices_empty" not in kinds and "no_plugins" not in kinds


def test_platform_field_is_not_derived() -> None:
    # Guard the verification finding: even though _ANDROID carries platform "Linux armv8l", the mapper
    # must NOT emit nav_platform_os — the dataset's platform field is not faithfully paired with the UA,
    # so feeding it to the platform-coherence rules would fabricate a mismatch. (The genuine sub-problem —
    # real Android reporting a Linux platform — is fixed by OS-family resolution on the real-browser
    # derivation paths, not here.)
    assert _ANDROID["platform"] == "Linux armv8l"
    sigs = {s.kind: s.value for s in intoli_signals(_ANDROID, "a", NOW)}
    assert "nav_platform_os" not in sigs


def test_real_android_is_clean() -> None:
    # A real Android visitor must not be convicted by the corpus — without the unreliable platform field,
    # the faithfully-paired UA/vendor/language/screen signals are all coherent.
    verdict = Detector().score(group_signals(intoli_signals(_ANDROID, "a", NOW))[0])
    assert verdict.label.value == "human"


def test_real_desktop_is_clean() -> None:
    verdict = Detector().score(group_signals(intoli_signals(_DESKTOP, "d", NOW))[0])
    assert verdict.label.value == "human"


def test_ios_chrome_does_not_emit_vendor_engine() -> None:
    # On iOS the vendor/UA-engine axes decouple (Apple forces WebKit, vendor follows the brand), so the
    # mapper must ABSTAIN — no vendor_engine signal → br.vendor_vs_ua cannot fire ("unknown never fires").
    kinds = {s.kind for s in intoli_signals(_IOS_CHROME, "i", NOW)}
    assert "vendor_engine" not in kinds
    assert "ua_engine" in kinds  # the engine signal is still emitted (other rules read it)


def test_real_ios_chrome_is_clean() -> None:
    # Regression guard for the v0.74.22 fix: a real Chrome-iOS visitor must NOT be convicted on
    # br.vendor_vs_ua (it scored bot 100% before the iOS gate).
    verdict = Detector().score(group_signals(intoli_signals(_IOS_CHROME, "i", NOW))[0])
    assert "br.vendor_vs_ua" not in {c.rule_id for c in verdict.contradictions}
    assert verdict.label.value == "human"


def test_desktop_vendor_mismatch_still_convicts() -> None:
    # Positive control: the iOS gate must narrow ONLY iOS. A DESKTOP UA whose vendor contradicts the UA
    # engine (Windows Chrome UA → chromium, but vendor "Apple…" → safari) is a real spoof and must still
    # trip br.vendor_vs_ua.
    spoof = {**_DESKTOP, "vendor": "Apple Computer, Inc."}
    verdict = Detector().score(group_signals(intoli_signals(spoof, "s", NOW))[0])
    assert "br.vendor_vs_ua" in {c.rule_id for c in verdict.contradictions}
