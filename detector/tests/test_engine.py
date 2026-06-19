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


def test_active_rules_are_live_producible() -> None:
    # Drift guard: every *active* rule must read a signal that some component (collector TS, the inline
    # demo collector, the edge, or the detector) actually emits. An active rule reading an unemitted
    # signal is silently dead — exactly the class of bug the webdriverSpoofed collector drift created.
    # Rules awaiting a producer must be `experimental` (e.g. tcp_os_hint, is_proxy_exit), not `active`.
    import re

    import yaml

    from kitsune_detector.contracts import contracts_dir

    root = contracts_dir().parent
    emitted: set[str] = set()
    for py in (root / "detector" / "src").rglob("*.py"):
        text = py.read_text()
        emitted.update(re.findall(r'kind\s*=\s*["\'](\w+)["\']', text))  # detector/reputation/derived
        emitted.update(k for _, k in re.findall(r'S\(\s*"(\w+)"\s*,\s*"(\w+)"', text))  # inline demo collector
    for ts in (root / "collector" / "src").rglob("*.ts"):
        emitted.update(k for _, k in re.findall(r'sig\(\s*"(\w+)"\s*,\s*"(\w+)"', ts.read_text()))
    for go in (root / "edge").rglob("*.go"):
        if go.name.endswith("_test.go"):
            continue
        emitted.update(re.findall(r'(?:Network|Browser|Behavioral|Reputation)\([^,]+,\s*"(\w+)"', go.read_text()))

    raw = yaml.safe_load((contracts_dir() / "rules" / "registry.yaml").read_text())
    dead = [
        f"{r['id']} reads {rd} but no component emits '{rd.split('.', 1)[1]}'"
        for r in raw["rules"]
        if r.get("status") == "active"
        for rd in r.get("reads", [])
        if rd.split(".", 1)[1] not in emitted
    ]
    assert not dead, "active rules with no live producer (mark experimental or wire a producer):\n" + "\n".join(dead)


def test_registry_rules_are_well_formed() -> None:
    # Registry invariants that keep the generic engine safe. The arity check matters most: a not_equal
    # or equals rule with the wrong number of reads would index a missing value at evaluation time
    # (a runtime crash on live traffic), so it must be impossible to commit one.
    import yaml

    from kitsune_detector.contracts import contracts_dir

    arity = {"present": 1, "absent": 1, "equals": 2, "not_equal": 2, "below_threshold": 1, "above_threshold": 1}
    needs_threshold = {"below_threshold", "above_threshold"}
    raw = yaml.safe_load((contracts_dir() / "rules" / "registry.yaml").read_text())
    problems: list[str] = []
    for r in raw["rules"]:
        if r.get("status") == "retired":
            continue
        rid, pred, reads = r.get("id"), r.get("predicate"), r.get("reads", [])
        for field in ("id", "title", "layers", "reads", "predicate", "weight", "status"):
            if field not in r:
                problems.append(f"{rid}: missing required field {field}")
        if pred not in arity:
            problems.append(f"{rid}: unknown predicate {pred!r}")
            continue
        if len(reads) != arity[pred]:
            problems.append(f"{rid}: predicate {pred} needs {arity[pred]} reads, has {len(reads)}")
        if (pred in needs_threshold) != ("threshold" in r):
            problems.append(f"{rid}: threshold presence must match predicate {pred}")
    assert not problems, "registry invariant violations:\n" + "\n".join(problems)


def test_every_active_rule_declares_a_category() -> None:
    # The detection-class taxonomy (coherence/artifact = spoofing caught; environment/automation =
    # headless too) is only meaningful if every rule states its class explicitly. Relying on the model
    # default silently mis-buckets an environment/automation rule as coherence, skewing the scoreboard.
    import yaml

    from kitsune_detector.contracts import contracts_dir

    raw = yaml.safe_load((contracts_dir() / "rules" / "registry.yaml").read_text())
    missing = [r["id"] for r in raw["rules"] if r.get("status") != "retired" and "category" not in r]
    assert not missing, f"active rules missing an explicit category: {missing}"


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
        (
            [
                (Layer.network, "h2_settings_hint", "firefox", Source.edge),
                (Layer.network, "h2_browser_hint", "chrome", Source.edge),
            ],
            "net.h2_settings_vs_order",
        ),
        (
            [
                (Layer.network, "accept_language_primary", "en", Source.edge),
                (Layer.browser, "nav_language_primary", "de", Source.collector),
            ],
            "net.accept_lang_vs_navigator",
        ),
        (
            [
                (Layer.network, "ch_platform_header", "Linux", Source.edge),
                (Layer.browser, "ua_platform", "Windows", Source.collector),
            ],
            "net.ch_platform_header_vs_ua",
        ),
        (
            [
                (Layer.network, "ch_ua_browser", "chrome", Source.edge),
                (Layer.browser, "ua_browser", "firefox", Source.collector),
            ],
            "net.ch_ua_vs_ua_browser",
        ),
        ([(Layer.browser, "ua_is_headless", True, Source.collector)], "br.headless_ua"),
        (
            [(Layer.behavioral, "keystroke_entropy", 0.05, Source.collector)],
            "bh.keystroke_entropy_floor",
        ),
        ([(Layer.reputation, "is_proxy_exit", True, Source.detector)], "rep.known_proxy_exit"),
        ([(Layer.behavioral, "mouse_straightness", 0.99, Source.collector)], "bh.path_too_straight"),
        ([(Layer.behavioral, "mouse_velocity_cv", 0.02, Source.collector)], "bh.uniform_velocity"),
        ([(Layer.behavioral, "power_law_exponent", 0.0, Source.collector)], "bh.power_law_violation"),
        (
            [(Layer.behavioral, "coalesced_events_absent", True, Source.collector)],
            "bh.synthetic_no_coalesced",
        ),
        ([(Layer.browser, "webdriver_spoofed", True, Source.collector)], "br.webdriver_spoofed"),
        ([(Layer.browser, "webgl_software", True, Source.collector)], "br.webgl_software"),
        ([(Layer.browser, "permissions_anomaly", True, Source.collector)], "br.permissions_anomaly"),
        ([(Layer.browser, "chrome_object_missing", True, Source.collector)], "br.no_chrome_object"),
        ([(Layer.browser, "function_tostring_tampered", True, Source.collector)], "br.tostring_tampered"),
        ([(Layer.browser, "hardware_concurrency", 0, Source.collector)], "br.low_hardware_concurrency"),
        ([(Layer.browser, "plugins_count", 0, Source.collector)], "br.no_plugins"),
        ([(Layer.browser, "webgl_getparameter_tampered", True, Source.collector)], "br.webgl_getparameter_tampered"),
        ([(Layer.browser, "plugins_spoofed", True, Source.collector)], "br.plugins_spoofed"),
        ([(Layer.browser, "nav_property_spoofed", True, Source.collector)], "br.nav_property_spoofed"),
        ([(Layer.browser, "webdriver_getter_tampered", True, Source.collector)], "br.webdriver_getter_tampered"),
        (
            [(Layer.browser, "notification_getter_tampered", True, Source.collector)],
            "br.notification_getter_tampered",
        ),
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
            [(Layer.browser, "webgl_worker_divergence", True, Source.collector)],
            "br.webgl_worker_vs_main",
        ),
        (
            [(Layer.browser, "canvas_worker_divergence", True, Source.collector)],
            "br.canvas_worker_vs_main",
        ),
        (
            [(Layer.browser, "timezone_worker_divergence", True, Source.collector)],
            "br.timezone_worker_vs_main",
        ),
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
        ([(Layer.browser, "audio_missing", True, Source.collector)], "br.audio_missing"),
        ([(Layer.browser, "audio_noise", True, Source.collector)], "br.audio_noise"),
        ([(Layer.browser, "media_devices_empty", True, Source.collector)], "br.media_devices_empty"),
        ([(Layer.browser, "adblock_present", True, Source.collector)], "br.adblock_present"),
        ([(Layer.browser, "macos_dpr1", True, Source.collector)], "br.macos_dpr1"),
        ([(Layer.browser, "font_linux_leak", True, Source.collector)], "br.font_linux_leak"),
        ([(Layer.browser, "font_mac_internal", True, Source.collector)], "br.font_mac_internal"),
        ([(Layer.browser, "codec_os_incoherent", True, Source.collector)], "br.codec_os_incoherent"),
        ([(Layer.browser, "cdp_runtime_enabled", True, Source.collector)], "br.cdp_runtime_enabled"),
        ([(Layer.browser, "csp_bypassed", True, Source.collector)], "br.csp_bypassed"),
        ([(Layer.browser, "webrtc_unavailable", True, Source.collector)], "br.webrtc_unavailable"),
        ([(Layer.browser, "timezone_inconsistent", True, Source.collector)], "br.timezone_inconsistent"),
        ([(Layer.browser, "engine_stack_mismatch", True, Source.collector)], "br.engine_stack_vs_ua"),
        ([(Layer.browser, "webgpu_webgl_mismatch", True, Source.collector)], "br.webgpu_webgl_vs"),
        ([(Layer.browser, "webgpu_vendor_mismatch", True, Source.collector)], "br.webgpu_vendor_vs_webgl"),
        ([(Layer.browser, "error_engine_mismatch", True, Source.collector)], "br.error_engine_vs_ua"),
        ([(Layer.browser, "math_engine_mismatch", True, Source.collector)], "br.math_engine_vs_ua"),
        ([(Layer.network, "sec_fetch_missing", True, Source.edge)], "net.sec_fetch_vs_ua"),
        ([(Layer.network, "accept_encoding_no_brotli", True, Source.edge)], "net.accept_encoding_vs_ua"),
        ([(Layer.network, "tls_no_grease", True, Source.edge)], "net.tls_grease_vs_ua"),
        ([(Layer.network, "tls_no_pq_keyshare", True, Source.edge)], "net.tls_pq_keyshare_vs_ua"),
        ([(Layer.network, "h2_engine_unknown", True, Source.edge)], "net.h2_unknown_vs_ua"),
        ([(Layer.network, "quic_no_grease", True, Source.edge)], "net.quic_grease_vs_ua"),
        ([(Layer.network, "quic_no_pq_keyshare", True, Source.edge)], "net.quic_pq_keyshare_vs_ua"),
        ([(Layer.browser, "automation_globals", True, Source.collector)], "br.automation_globals"),
        ([(Layer.browser, "screen_impossible", True, Source.collector)], "br.screen_impossible"),
        ([(Layer.network, "ch_ua_mobile_mismatch", True, Source.edge)], "net.ch_ua_mobile_vs_ua"),
        (
            [(Layer.network, "ch_ua_no_grease_brand", True, Source.edge)],
            "net.ch_ua_no_grease_brand",
        ),
        ([(Layer.network, "ch_ua_version_mismatch", True, Source.edge)], "net.ch_ua_version_vs_ua"),
        (
            [
                (Layer.network, "tcp_kernel", "linux", Source.edge),
                (Layer.network, "ua_kernel", "windows", Source.edge),
            ],
            "net.tcp_os_vs_ua",
        ),
        ([(Layer.network, "h2_rapid_reset", True, Source.edge)], "net.h2_rapid_reset"),
        ([(Layer.network, "h2_continuation_flood", True, Source.edge)], "net.h2_continuation_flood"),
        ([(Layer.network, "h2_control_flood", True, Source.edge)], "net.h2_control_flood"),
        ([(Layer.browser, "rfp_browser", True, Source.collector)], "br.rfp_browser"),
        ([(Layer.browser, "canvas_noise", True, Source.collector)], "br.canvas_noise"),
        (
            [
                (Layer.browser, "webrtc_public_ip", "203.0.113.7", Source.collector),
                (Layer.network, "observed_ip", "198.51.100.2", Source.edge),
            ],
            "net.webrtc_ip_vs_observed",
        ),
    ],
)
def test_v2_rules_fire(signals_spec, rule_id: str) -> None:
    sigs = [make_signal("s", layer, kind, value, source=src) for (layer, kind, value, src) in signals_spec]
    session = group_signals(sigs)[0]
    engine = CoherenceEngine(load_registry())
    fired = {c.rule_id for c in engine.evaluate(session)}
    assert rule_id in fired


def test_matching_ch_platform_does_not_fire() -> None:
    # The HTTP client hint and the JS UA platform agree → no cross-layer OS contradiction.
    sigs = [
        make_signal("s", Layer.network, "ch_platform_header", "Windows", source=Source.edge),
        make_signal("s", Layer.browser, "ua_platform", "Windows", source=Source.collector),
    ]
    session = group_signals(sigs)[0]
    fired = {c.rule_id for c in CoherenceEngine(load_registry()).evaluate(session)}
    assert "net.ch_platform_header_vs_ua" not in fired


def test_matching_h2_engine_does_not_fire() -> None:
    # A real browser's h2 stack agrees with its UA, its TLS engine, and its own SETTINGS profile.
    sigs = [
        make_signal("s", Layer.network, "h2_browser_hint", "chrome", source=Source.edge),
        make_signal("s", Layer.network, "h2_settings_hint", "chrome", source=Source.edge),
        make_signal("s", Layer.network, "ja4_browser_hint", "chrome", source=Source.edge),
        make_signal("s", Layer.browser, "ua_browser", "chrome", source=Source.collector),
    ]
    session = group_signals(sigs)[0]
    fired = {c.rule_id for c in CoherenceEngine(load_registry()).evaluate(session)}
    assert not ({"net.h2_vs_ua_browser", "net.h2_vs_tls_browser", "net.h2_settings_vs_order"} & fired)


def test_matching_accept_language_does_not_fire() -> None:
    # Same primary language across the HTTP and JS layers (region nuance ignored) → no contradiction.
    sigs = [
        make_signal("s", Layer.network, "accept_language_primary", "en", source=Source.edge),
        make_signal("s", Layer.browser, "nav_language_primary", "en", source=Source.collector),
    ]
    session = group_signals(sigs)[0]
    fired = {c.rule_id for c in CoherenceEngine(load_registry()).evaluate(session)}
    assert "net.accept_lang_vs_navigator" not in fired


def test_webrtc_ip_matches_observed_does_not_fire() -> None:
    # A direct (un-proxied) client: the WebRTC IP equals the observed connection IP → no contradiction.
    sigs = [
        make_signal("s", Layer.browser, "webrtc_public_ip", "203.0.113.7", source=Source.collector),
        make_signal("s", Layer.network, "observed_ip", "203.0.113.7", source=Source.edge),
    ]
    session = group_signals(sigs)[0]
    fired = {c.rule_id for c in CoherenceEngine(load_registry()).evaluate(session)}
    assert "net.webrtc_ip_vs_observed" not in fired
