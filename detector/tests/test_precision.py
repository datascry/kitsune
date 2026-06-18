# tests/test_precision — the other half of the detector: legitimate humans must NOT be flagged.
# Diverse realistic, coherent profiles (incl. touch laptops and external-monitor Macs) score human.

from __future__ import annotations

import pytest

from kitsune_detector.detector import Detector
from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Label, Layer, Session, Source

from .conftest import make_signal


def _human(session_id: str, browser: dict[str, object]) -> Session:
    """A coherent human session: real values, present capabilities, and crucially NONE of the boolean
    tell-signals (no webgl2_missing, voices_empty, webdriver=true, …). Behaviour is human-like."""
    sigs = [
        make_signal(session_id, Layer.network, "ja4_browser_hint", browser["ja4_browser"], source=Source.edge),
        make_signal(session_id, Layer.network, "ja4_os_hint", browser["ja4_os"], source=Source.edge),
        make_signal(session_id, Layer.network, "tcp_os_hint", browser["ja4_os"], source=Source.edge),
        make_signal(session_id, Layer.browser, "webdriver", False),
        make_signal(session_id, Layer.behavioral, "mouse_entropy", 0.61),
        make_signal(session_id, Layer.behavioral, "pointer_event_count", 180),
        make_signal(session_id, Layer.behavioral, "keystroke_entropy", 0.74),
        make_signal(session_id, Layer.reputation, "asn_is_datacenter", False),
    ]
    for kind, value in browser.items():
        if kind in ("ja4_browser", "ja4_os"):
            continue
        sigs.append(make_signal(session_id, Layer.browser, kind, value))
    return group_signals(sigs)[0]


# Realistic, fully-coherent humans across OS/browser combinations — and two notorious false-positive
# edge cases: a Windows touch laptop (maxTouchPoints > 0) and a Mac on an external 1080p monitor (dPR 1).
HUMANS = {
    "win-chrome": {
        "ja4_browser": "chrome",
        "ja4_os": "windows",
        "ua_browser": "chrome",
        "ua_platform": "Windows",
        "ch_platform": "Windows",
        "vendor_engine": "chromium",
        "ua_engine": "chromium",
        "hardware_concurrency": 8,
        "plugins_count": 5,
    },
    "mac-chrome-retina": {
        "ja4_browser": "chrome",
        "ja4_os": "macOS",
        "ua_browser": "chrome",
        "ua_platform": "macOS",
        "ch_platform": "macOS",
        "vendor_engine": "chromium",
        "ua_engine": "chromium",
        "hardware_concurrency": 10,
        "plugins_count": 5,
    },
    "linux-firefox": {
        "ja4_browser": "firefox",
        "ja4_os": "Linux",
        "ua_browser": "firefox",
        "ua_platform": "Linux",
        "vendor_engine": "firefox",
        "ua_engine": "firefox",
        "oscpu_os": "Linux",
        "nav_platform_os": "Linux",
        "hardware_concurrency": 12,
    },
    "win-touch-laptop": {
        "ja4_browser": "chrome",
        "ja4_os": "windows",
        "ua_browser": "chrome",
        "ua_platform": "Windows",
        "ch_platform": "Windows",
        "vendor_engine": "chromium",
        "ua_engine": "chromium",
        "hardware_concurrency": 8,
        "plugins_count": 5,
        # a real 2-in-1 touchscreen laptop: touch present on a desktop UA.
        "maxtouch_desktop": True,
    },
    "mac-external-monitor": {
        "ja4_browser": "chrome",
        "ja4_os": "macOS",
        "ua_browser": "chrome",
        "ua_platform": "macOS",
        "ch_platform": "macOS",
        "vendor_engine": "chromium",
        "ua_engine": "chromium",
        "hardware_concurrency": 10,
        "plugins_count": 5,
        # a Mac mini / desktop Mac on a 1080p external display → dPR 1.0.
        "macos_dpr1": True,
    },
    "corporate-vdi": {
        "ja4_browser": "chrome",
        "ja4_os": "windows",
        "ua_browser": "chrome",
        "ua_platform": "Windows",
        "ch_platform": "Windows",
        "vendor_engine": "chromium",
        "ua_engine": "chromium",
        "hardware_concurrency": 4,
        "plugins_count": 5,
        # a real corporate VDI / VM session: no passthrough GPU → llvmpipe/SwiftShader software WebGL.
        "webgl_software": True,
    },
}


@pytest.mark.parametrize("name", sorted(HUMANS))
def test_legitimate_human_not_flagged(detector: Detector, name: str) -> None:
    verdict = detector.score(_human(name, HUMANS[name]))
    assert verdict.label is Label.human, (
        f"{name} false-positived as {verdict.label.value} ({verdict.score:.2f}): "
        f"{sorted(c.rule_id for c in verdict.contradictions)}"
    )
