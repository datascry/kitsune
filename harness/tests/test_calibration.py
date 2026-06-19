# harness/tests/test_calibration — the real-browser calibration scorer + fingerprint mapper.
# A coherent real fingerprint must score human (no tells); unusual configs surface the expected FPs.

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kitsune_detector.detector import Detector
from kitsune_detector.ingest import group_signals
from kitsune_detector.models import RuleCategory

from kitsune_harness.calibration import (
    DERIVABLE_KINDS,
    _font_os,
    _nav_platform_os,
    _os_family,
    _ua_engine,
    _ua_platform,
    _vendor_engine,
    _webgl_os,
    calibrate,
    render_report,
    signals_from_fingerprint,
)

NOW = datetime(2026, 6, 18, tzinfo=UTC)

CHROME_MAC = {
    "navigator": {
        "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",  # noqa: E501
        "platform": "MacIntel",
        "languages": ["en-US"],
        "hardwareConcurrency": 8,
        "deviceMemory": 8,
        "vendor": "Google Inc.",
        "productSub": "20030107",
        "oscpu": None,
        "maxTouchPoints": 0,
        "webdriver": False,
    },
    "userAgentData": {
        "platform": "macOS",
        "brands": [{"brand": "Google Chrome", "version": "147"}, {"brand": "Chromium", "version": "147"}],
        "fullVersionList": [{"brand": "Google Chrome", "version": "147.0.7727.138"}],
        "uaFullVersion": "147.0.7727.138",
    },
    "screen": {
        "width": 1470,
        "height": 956,
        "availWidth": 1470,
        "availHeight": 922,
        "colorDepth": 30,
        "devicePixelRatio": 2,
        "outerWidth": 1470,
        "outerHeight": 922,
    },
    "videoCard": {
        "renderer": "ANGLE (Intel, ANGLE Metal Renderer: Intel(R) Iris(TM) Plus Graphics 655, Unspecified Version)",
        "vendor": "Google Inc. (Intel)",
    },
    "audioCodecs": {"aac": "probably"},
    "videoCodecs": {"h264": "probably"},
    "multimediaDevices": {
        "speakers": [{"kind": "audiooutput"}],
        "micros": [{"kind": "audioinput"}],
        "webcams": [{"kind": "videoinput"}],
    },
    "fonts": ["Helvetica Neue", "Menlo", "Geneva", "Monaco"],
    "pluginsData": {"plugins": [{"name": "PDF Viewer"}], "mimeTypes": [{"type": "application/pdf"}]},
}


def _kinds(signals: list) -> dict[str, object]:
    return {s.kind: s.value for s in signals}


def test_helpers_cover_all_branches() -> None:
    assert _ua_platform("x Windows y") == "Windows"
    assert _ua_platform("x Macintosh y") == "macOS"
    assert _ua_platform("x Android y") == "Android"
    assert _ua_platform("x Linux y") == "Linux"
    assert _ua_platform("nothing") == "unknown"
    assert _ua_engine("Firefox/120") == "firefox"
    assert _ua_engine("Chrome/147") == "chromium"
    assert _ua_engine("Version/17 Safari/605") == "safari"
    assert _ua_engine("curl") == "other"
    assert _vendor_engine("Google Inc.") == "chromium"
    assert _vendor_engine("") == "firefox"
    assert _vendor_engine("Apple Computer, Inc.") == "safari"
    assert _vendor_engine("Other") == "other"
    assert _webgl_os("ANGLE (... Direct3D11 ...)") == "Windows"
    assert _webgl_os("ANGLE (... Metal ...)") == "macOS"
    assert _webgl_os("ANGLE (... Vulkan ...)") == "Linux"
    assert _webgl_os("plain") == ""
    assert _nav_platform_os("MacIntel") == "macOS"
    assert _nav_platform_os("Win32") == "Windows"
    assert _nav_platform_os("Linux x86_64") == "Linux"
    assert _nav_platform_os("Android") == "Android"
    assert _nav_platform_os("") == ""
    assert _font_os(["Segoe UI", "Calibri", "Tahoma"]) == "Windows"
    assert _font_os(["Helvetica"]) == ""


def test_os_family_resolves_android_linux_kernel() -> None:
    # Android IS Linux: a "Linux" kernel hint under an Android UA resolves to the OS family "Android",
    # so the platform-coherence rules see agreement, not a contradiction (the 73% real-mobile FP).
    assert _os_family("Linux", "Android") == "Android"
    # Desktop OS impersonation is untouched — a Linux host claiming Windows still contradicts.
    assert _os_family("Linux", "Windows") == "Linux"
    assert _os_family("Windows", "Android") == "Windows"
    assert _os_family("Linux", "Linux") == "Linux"


def test_coherent_real_chrome_scores_human() -> None:
    sigs = signals_from_fingerprint(CHROME_MAC, "p1", NOW)
    verdict = Detector().ingest_and_score(sigs)[0]
    assert verdict.label.value == "human", [c.rule_id for c in verdict.contradictions]
    k = _kinds(sigs)
    # identity values emitted, no tell signals fired
    assert k["ua_platform"] == "macOS" and k["ua_engine"] == "chromium" and k["webgl_os_hint"] == "macOS"
    assert "webgl_software" not in k and "ch_he_headless" not in k and "media_devices_empty" not in k


def test_unusual_but_legit_configs_surface_expected_tells() -> None:
    # A real Intel Mac without a Retina display (dpr 1) trips macos_dpr1 — exactly the FP to catch.
    mac_dpr1 = {**CHROME_MAC, "screen": {**CHROME_MAC["screen"], "devicePixelRatio": 1}}
    assert "macos_dpr1" in _kinds(signals_from_fingerprint(mac_dpr1, "p", NOW))
    # A VM / software-WebGL renderer trips webgl_software.
    vm = {**CHROME_MAC, "videoCard": {"renderer": "ANGLE (Google, Vulkan (SwiftShader Device), SwiftShader driver)"}}
    assert "webgl_software" in _kinds(signals_from_fingerprint(vm, "p", NOW))
    # No media devices (headless-like container) trips media_devices_empty.
    nodev = {**CHROME_MAC, "multimediaDevices": {"speakers": [], "micros": [], "webcams": []}}
    assert "media_devices_empty" in _kinds(signals_from_fingerprint(nodev, "p", NOW))
    # A HeadlessChrome brand in the high-entropy list trips ch_he_headless.
    headless = {
        **CHROME_MAC,
        "userAgentData": {
            **CHROME_MAC["userAgentData"],
            "fullVersionList": [{"brand": "HeadlessChrome", "version": "147.0.0.0"}],
        },
    }
    assert "ch_he_headless" in _kinds(signals_from_fingerprint(headless, "p", NOW))
    # Empty languages / bare renderer / version mismatch / linux-font leak / stripped screen.
    weird = {
        **CHROME_MAC,
        "navigator": {**CHROME_MAC["navigator"], "languages": [], "platform": ""},
        "userAgentData": {
            **CHROME_MAC["userAgentData"],
            "uaFullVersion": "120.0.0.0",
            "fullVersionList": [{"brand": "Chromium", "version": "120.0.0.0"}],
        },
        "videoCard": {"renderer": "NVIDIA GeForce RTX 3080"},
        "screen": {
            "width": 0,
            "height": 0,
            "availWidth": 0,
            "availHeight": 0,
            "colorDepth": 16,
            "devicePixelRatio": 0,
            "outerWidth": 0,
            "outerHeight": 0,
        },
        "fonts": ["Arimo", "Cousine"],
        "audioCodecs": {},
        "videoCodecs": {},
        "multimediaDevices": {},
        "pluginsData": {"plugins": [], "mimeTypes": []},
    }
    k = _kinds(signals_from_fingerprint(weird, "p", NOW))
    for tell in (
        "languages_empty",
        "platform_empty",
        "webgl_not_angle",
        "ch_he_version_vs_ua",
        "screen_zero",
        "color_depth_anomaly",
        "devicepixelratio_anomaly",
        "font_linux_leak",
        "codec_os_incoherent",
        "mimetypes_empty",
        "chrome_no_pdfviewer",
    ):
        assert tell in k, tell


def test_firefox_linux_and_mac_internal_font() -> None:
    ff = {
        "navigator": {
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
            "platform": "Linux x86_64",
            "languages": ["en"],
            "hardwareConcurrency": 4,
            "deviceMemory": None,
            "vendor": "",
            "productSub": "20100101",
            "oscpu": "Linux x86_64",
            "maxTouchPoints": 0,
            "webdriver": False,
        },
        "userAgentData": None,
        "screen": {
            "width": 1920,
            "height": 1080,
            "availWidth": 1920,
            "availHeight": 1050,
            "colorDepth": 24,
            "devicePixelRatio": 1,
            "outerWidth": 1920,
            "outerHeight": 1050,
        },
        "videoCard": {"renderer": "Mesa Intel(R) UHD Graphics"},
        "audioCodecs": {"aac": ""},
        "videoCodecs": {"h264": ""},
        "multimediaDevices": {"speakers": [{"kind": "audiooutput"}]},
        "fonts": ["DejaVu Sans", "Liberation Sans", "Ubuntu", ".Aqua Kana"],
        "pluginsData": {"plugins": [], "mimeTypes": []},
    }
    k = _kinds(signals_from_fingerprint(ff, "p", NOW))
    assert k["ua_engine"] == "firefox" and k["ua_render"] == "gecko" and k["oscpu_os"] == "Linux"
    assert "webgl_software" in k  # Mesa
    assert "font_mac_internal" in k  # .Aqua Kana present
    assert "chrome_no_devicememory" not in k  # firefox is not chromium → gated off


def test_calibrate_and_report() -> None:
    profiles = [
        ("good", signals_from_fingerprint(CHROME_MAC, "good", NOW)),
        (
            "vm",
            signals_from_fingerprint(
                {**CHROME_MAC, "videoCard": {"renderer": "ANGLE (Google, SwiftShader)"}}, "vm", NOW
            ),
        ),
    ]
    report = calibrate(Detector(), profiles)
    assert report.n_profiles == 2
    by_id = {s.rule_id: s for s in report.rule_stats}
    assert by_id["br.webgl_software"].calibrated
    assert by_id["br.webgl_software"].fired == 1 and by_id["br.webgl_software"].total == 2
    # a runtime-only rule is not calibrated
    assert not by_id["br.cdp_runtime_enabled"].calibrated
    out = render_report(report, fp_threshold=0.0)
    assert "Kitsune calibration" in out and "br.webgl_software" in out and "Verdict distribution" in out


_ENGINES_DIR = Path(__file__).resolve().parents[2] / "corpus" / "calibration" / "engines"

# The convicting coherence/artifact rules that may fire on each REAL (Tier-2) engine capture. A real
# browser engine is internally coherent, so chromium/firefox must trip NONE. The one allowed fire —
# `br.navplatform_vs_ua` on webkit — is a property of the *capture*, not a rule bug: Playwright's WebKit
# on Linux serves a macOS Safari UA while `navigator.platform` leaks `Linux x86_64` (the container), a
# genuine Mac-UA-vs-Linux-platform contradiction a real Safari on a real Mac would never produce.
_EXPECTED_CONVICTING_COHERENCE: dict[str, set[str]] = {
    "chromium": set(),
    "firefox": set(),
    "webkit": {"br.navplatform_vs_ua"},
}


def test_real_engine_captures_trip_no_spurious_coherence() -> None:
    """Tier-2 over-leverage guard, as an enforced gate: scoring the real Chromium/Firefox/WebKit captures
    must surface no *new* convicting coherence/artifact rule. This is the second, independent source that
    refutes a single-source (browserforge) FP number — a coherence rule that starts firing here is an FP
    on a real browser, the exact regression the calibration discipline exists to catch."""
    det = Detector()
    convicting = {RuleCategory.coherence, RuleCategory.artifact}
    for path in sorted(_ENGINES_DIR.glob("*.json")):
        name = path.stem
        fp = json.loads(path.read_text())
        sigs = signals_from_fingerprint(fp, name, NOW)
        verdict = det.score(group_signals(sigs)[0])
        fired = {c.rule_id for c in verdict.contradictions if c.category in convicting}
        expected = _EXPECTED_CONVICTING_COHERENCE.get(name, set())
        assert fired == expected, f"{name}: convicting coherence/artifact fires changed: {fired} != {expected}"


def test_derivable_kinds_are_a_subset_of_real_rule_reads() -> None:
    # every derivable kind should be a browser signal some rule actually reads (no dead mappings)
    from kitsune_detector.contracts import load_rule_registry

    _, rules = load_rule_registry()
    read = {
        ref.split(".", 1)[1]
        for r in rules
        if r.get("status") != "retired"
        for ref in r.get("reads", [])
        if ref.startswith("browser.")
    }
    assert read >= DERIVABLE_KINDS
