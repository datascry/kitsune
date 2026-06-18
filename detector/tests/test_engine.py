# tests/test_engine — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

import pytest

from kitsune_detector.coherence import load_registry
from kitsune_detector.coherence.engine import CoherenceEngine
from kitsune_detector.coherence.rules import CoherenceRule, RuleSet
from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Layer, Session, Source

from .conftest import make_signal


def test_engine_flags_bot_incoherence(bot_session: Session) -> None:
    engine = CoherenceEngine(load_registry())
    fired = {c.rule_id for c in engine.evaluate(bot_session)}
    # A representative spread across all four layers.
    assert {
        "net.tls_os_vs_tcp_os",
        "net.tls_vs_ua_browser",
        "br.ua_platform_vs_ch_platform",
        "br.webdriver_present",
        "rep.datacenter_asn",
    } <= fired


def test_engine_clears_human(human_session: Session) -> None:
    engine = CoherenceEngine(load_registry())
    assert engine.evaluate(human_session) == []


def test_engine_exposes_ruleset_version() -> None:
    engine = CoherenceEngine(load_registry())
    assert engine.ruleset_version


def test_engine_skips_retired_rules(bot_session: Session) -> None:
    retired = CoherenceRule(
        id="br.webdriver_present",
        title="t",
        layers=[Layer.browser],
        reads=["browser.webdriver"],
        predicate="present",
        weight=0.9,
        status="retired",
    )
    engine = CoherenceEngine(RuleSet(ruleset_version="0", rules=[retired]))
    assert engine.evaluate(bot_session) == []


@pytest.mark.parametrize(
    ("signals_spec", "rule_id"),
    [
        (
            [
                (Layer.network, "h2_browser_hint", "firefox", Source.edge),
                (Layer.network, "ja4_browser_hint", "chrome", Source.edge),
            ],
            "net.h2_vs_tls_browser",
        ),
        ([(Layer.browser, "ua_is_headless", True, Source.collector)], "br.headless_ua"),
        (
            [(Layer.behavioral, "keystroke_entropy", 0.05, Source.collector)],
            "bh.keystroke_entropy_floor",
        ),
        ([(Layer.reputation, "is_proxy_exit", True, Source.detector)], "rep.known_proxy_exit"),
        ([(Layer.behavioral, "mouse_straightness", 0.99, Source.collector)], "bh.path_too_straight"),
        ([(Layer.behavioral, "mouse_velocity_cv", 0.02, Source.collector)], "bh.uniform_velocity"),
        ([(Layer.browser, "webdriver_spoofed", True, Source.collector)], "br.webdriver_spoofed"),
        ([(Layer.browser, "webgl_software", True, Source.collector)], "br.webgl_software"),
        ([(Layer.browser, "permissions_anomaly", True, Source.collector)], "br.permissions_anomaly"),
        ([(Layer.browser, "chrome_object_missing", True, Source.collector)], "br.no_chrome_object"),
        ([(Layer.browser, "function_tostring_tampered", True, Source.collector)], "br.tostring_tampered"),
        ([(Layer.browser, "hardware_concurrency", 0, Source.collector)], "br.low_hardware_concurrency"),
        ([(Layer.browser, "plugins_count", 0, Source.collector)], "br.no_plugins"),
        ([(Layer.browser, "webgl_getparameter_tampered", True, Source.collector)], "br.webgl_getparameter_tampered"),
        ([(Layer.browser, "plugins_spoofed", True, Source.collector)], "br.plugins_spoofed"),
        ([(Layer.browser, "webdriver_getter_tampered", True, Source.collector)], "br.webdriver_getter_tampered"),
        (
            [
                (Layer.browser, "webgl_os_hint", "Windows", Source.collector),
                (Layer.browser, "ua_platform", "Linux", Source.collector),
            ],
            "br.webgl_os_vs_ua",
        ),
        (
            [
                (Layer.browser, "nav_platform_os", "Linux", Source.collector),
                (Layer.browser, "ua_platform", "macOS", Source.collector),
            ],
            "br.navplatform_vs_ua",
        ),
        ([(Layer.browser, "worker_divergence", True, Source.collector)], "br.worker_divergence"),
        (
            [
                (Layer.browser, "vendor_engine", "chromium", Source.collector),
                (Layer.browser, "ua_engine", "firefox", Source.collector),
            ],
            "br.vendor_vs_ua",
        ),
        (
            [
                (Layer.browser, "oscpu_os", "Linux", Source.collector),
                (Layer.browser, "ua_platform", "macOS", Source.collector),
            ],
            "br.oscpu_vs_ua",
        ),
        ([(Layer.browser, "languages_empty", True, Source.collector)], "br.languages_empty"),
        ([(Layer.browser, "screen_zero", True, Source.collector)], "br.screen_zero"),
        ([(Layer.browser, "chrome_no_connection", True, Source.collector)], "br.no_connection"),
        ([(Layer.browser, "chrome_no_pdfviewer", True, Source.collector)], "br.no_pdfviewer"),
        ([(Layer.browser, "chrome_runtime_missing", True, Source.collector)], "br.chrome_runtime_missing"),
        ([(Layer.browser, "maxtouch_desktop", True, Source.collector)], "br.maxtouch_desktop"),
        ([(Layer.browser, "mimetypes_empty", True, Source.collector)], "br.mimetypes_empty"),
        ([(Layer.browser, "chrome_no_devicememory", True, Source.collector)], "br.no_devicememory"),
        ([(Layer.browser, "notification_denied", True, Source.collector)], "br.notification_denied"),
        ([(Layer.browser, "platform_empty", True, Source.collector)], "br.platform_empty"),
        (
            [
                (Layer.browser, "productsub_render", "webkit", Source.collector),
                (Layer.browser, "ua_render", "gecko", Source.collector),
            ],
            "br.productsub_vs_ua",
        ),
        ([(Layer.browser, "cdc_artifacts", True, Source.collector)], "br.cdc_artifacts"),
        ([(Layer.browser, "webgl2_missing", True, Source.collector)], "br.webgl2_missing"),
        ([(Layer.browser, "iframe_divergence", True, Source.collector)], "br.iframe_divergence"),
        (
            [
                (Layer.browser, "font_os_hint", "Linux", Source.collector),
                (Layer.browser, "ua_platform", "Windows", Source.collector),
            ],
            "br.font_os_vs_ua",
        ),
        ([(Layer.browser, "screen_avail_invalid", True, Source.collector)], "br.screen_avail_invalid"),
        ([(Layer.browser, "color_depth_anomaly", True, Source.collector)], "br.color_depth_anomaly"),
        ([(Layer.browser, "devicepixelratio_anomaly", True, Source.collector)], "br.devicepixelratio_anomaly"),
        ([(Layer.browser, "hover_none_desktop", True, Source.collector)], "br.hover_none_desktop"),
        ([(Layer.browser, "pointer_touch_incoherent", True, Source.collector)], "br.pointer_touch_incoherent"),
        ([(Layer.browser, "voices_empty", True, Source.collector)], "br.voices_empty"),
        (
            [
                (Layer.browser, "voice_os_hint", "Linux", Source.collector),
                (Layer.browser, "ua_platform", "Windows", Source.collector),
            ],
            "br.voice_os_vs_ua",
        ),
        ([(Layer.browser, "webgl_renderer_artifact", True, Source.collector)], "br.webgl_renderer_artifact"),
    ],
)
def test_v2_rules_fire(signals_spec, rule_id: str) -> None:
    sigs = [make_signal("s", layer, kind, value, source=src) for (layer, kind, value, src) in signals_spec]
    session = group_signals(sigs)[0]
    engine = CoherenceEngine(load_registry())
    fired = {c.rule_id for c in engine.evaluate(session)}
    assert rule_id in fired
