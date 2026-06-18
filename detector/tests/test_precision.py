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
    ua_browser = browser["ua_browser"]
    locale = browser.get("locale", "en")
    sigs = [
        make_signal(session_id, Layer.network, "ja4_browser_hint", browser["ja4_browser"], source=Source.edge),
        make_signal(session_id, Layer.network, "ja4_os_hint", browser["ja4_os"], source=Source.edge),
        make_signal(session_id, Layer.network, "tcp_os_hint", browser["ja4_os"], source=Source.edge),
        make_signal(session_id, Layer.browser, "webdriver", False),
        make_signal(session_id, Layer.behavioral, "mouse_entropy", 0.61),
        make_signal(session_id, Layer.behavioral, "pointer_event_count", 180),
        make_signal(session_id, Layer.behavioral, "keystroke_entropy", 0.74),
        make_signal(session_id, Layer.reputation, "asn_is_datacenter", False),
        # Cross-layer facts a real browser keeps coherent across the HTTP and JS boundaries: the HTTP
        # stack and the JS layer agree on locale and the HTTP/2 engine. These exercise the cross-layer
        # rules' no-fire path, proving they do not false-positive (the locale is per-profile, not always en).
        make_signal(session_id, Layer.network, "accept_language_primary", locale, source=Source.edge),
        make_signal(session_id, Layer.browser, "nav_language_primary", locale),
        make_signal(session_id, Layer.network, "h2_browser_hint", ua_browser, source=Source.edge),
    ]
    # h2_settings_hint is only emitted for engines with a distinctive SETTINGS profile (Chrome/Firefox);
    # Safari's is "unknown" and not emitted, so a realistic Safari profile carries no settings hint.
    if ua_browser in ("chrome", "firefox"):
        sigs.append(make_signal(session_id, Layer.network, "h2_settings_hint", ua_browser, source=Source.edge))
    # A real device's TCP/IP kernel matches the OS its UA claims (Android runs Linux, iOS runs Darwin),
    # so net.tcp_os_vs_ua stays quiet — its no-fire path. The SYN-revealed kernel can't be spoofed.
    kernel = {"Windows": "windows", "macOS": "darwin", "Linux": "linux", "Android": "linux"}.get(
        str(browser["ua_platform"]), ""
    )
    if kernel:
        sigs.append(make_signal(session_id, Layer.network, "tcp_kernel", kernel, source=Source.edge))
        sigs.append(make_signal(session_id, Layer.network, "ua_kernel", kernel, source=Source.edge))
    # Sec-CH-UA(-Platform) are Chromium client hints; a real Chromium sends them matching its UA. Firefox
    # and Safari never send them, so their absence (not a mismatch) is the coherent case there.
    if "ch_platform" in browser:
        sigs.append(
            make_signal(session_id, Layer.network, "ch_platform_header", browser["ua_platform"], source=Source.edge)
        )
        sigs.append(make_signal(session_id, Layer.network, "ch_ua_browser", ua_browser, source=Source.edge))
    for kind, value in browser.items():
        if kind in ("ja4_browser", "ja4_os", "locale"):
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
    # macOS Safari — a non-Chromium, non-Firefox engine: no Sec-CH-UA(-Platform), no userAgentData, no
    # window.chrome. Tests that the Chromium- and Firefox-specific rules are correctly scoped and do not
    # fire on a browser that simply is not those engines.
    "mac-safari": {
        "ja4_browser": "safari",
        "ja4_os": "macOS",
        "ua_browser": "safari",
        "ua_platform": "macOS",
        "vendor_engine": "webkit",
        "ua_engine": "webkit",
        "oscpu_os": "macOS",
        "nav_platform_os": "macOS",
        "hardware_concurrency": 8,
    },
    # A German-locale Windows Chrome: Accept-Language and navigator.languages agree on "de", not "en".
    # Tests that the locale-coherence rule is language-agnostic (no hidden English assumption).
    "win-chrome-de": {
        "ja4_browser": "chrome",
        "ja4_os": "windows",
        "ua_browser": "chrome",
        "ua_platform": "Windows",
        "ch_platform": "Windows",
        "vendor_engine": "chromium",
        "ua_engine": "chromium",
        "hardware_concurrency": 8,
        "plugins_count": 5,
        "locale": "de",
    },
    # Android Chrome — a real mobile client: Android platform, coherent client hints. Tests that the
    # desktop-oriented rules do not assume a desktop OS and false-positive on a phone.
    "android-chrome": {
        "ja4_browser": "chrome",
        "ja4_os": "android",
        "ua_browser": "chrome",
        "ua_platform": "Android",
        "ch_platform": "Android",
        "vendor_engine": "chromium",
        "ua_engine": "chromium",
        "nav_platform_os": "Android",
        "hardware_concurrency": 8,
    },
}


@pytest.mark.parametrize("name", sorted(HUMANS))
def test_legitimate_human_not_flagged(detector: Detector, name: str) -> None:
    verdict = detector.score(_human(name, HUMANS[name]))
    assert verdict.label is Label.human, (
        f"{name} false-positived as {verdict.label.value} ({verdict.score:.2f}): "
        f"{sorted(c.rule_id for c in verdict.contradictions)}"
    )


def test_scripted_client_no_js_is_flagged(detector: Detector) -> None:
    # A network fingerprint (edge saw the TLS connection) but no browser layer — the collector never ran.
    # A scripted HTTP client (httpx/curl — the volumetric-DDoS case) that a coherence ruleset must catch.
    scripted = group_signals(
        [
            make_signal("s", Layer.network, "ja3", "abc", source=Source.edge),
            make_signal("s", Layer.network, "ja4", "t13d_x_y", source=Source.edge),
        ]
    )[0]
    verdict = detector.score(scripted)
    assert verdict.label is Label.bot
    assert "net.no_js_execution" in {c.rule_id for c in verdict.contradictions}
