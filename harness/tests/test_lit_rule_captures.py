# tests/test_lit_rule_captures — regression guard for the evader captures that light previously-unexercised rules.
# Each committed corpus capture must still trip the active convicting rule it was created to demonstrate.

from __future__ import annotations

import json
from pathlib import Path

import pytest
from kitsune_detector.detector import Detector
from kitsune_detector.models import Session

_CORPUS = Path(__file__).resolve().parents[2] / "corpus" / "sessions"

# capture file (in corpus/sessions) → the active convicting rule it was captured to demonstrate.
# These five were lit live (stealth evader modes) to close the no-test/no-capture constraint-#6 liability
# class; the captures freeze a detector-side regression guard so a rule/scoring change can't silently drop them.
_LIT = {
    "electron-leak": "br.electron_process",
    "stale-engine": "br.engine_feature_vs_ua",
    "measuretext-spoof": "br.measuretext_offscreen_vs",
    "canvas-lie": "br.canvas_lie",
    "domrect-spoof": "br.domrect_invariant",
    "cdc-leak": "br.cdc_artifacts",
    "font-os-leak": "br.font_os_vs_ua",
    "csp-bypass": "br.csp_bypassed",
    "audio-noise": "br.audio_noise",
    "screen-impossible": "br.screen_impossible",
    "h2-control-flood": "net.h2_control_flood",
    "h2-settings-split": "net.h2_settings_vs_order",
    "camoufox-macos": "br.font_mac_internal",
    "coalesce-proxy": "br.coalesced_untrusted",
    "apify-fp-inject": "br.worker_divergence",
    "go-tls-rotate": "net.ja4_unstable_within_session",
    "go-tls-h2-rotate": "net.h2_unstable_within_session",
    "go-tls-static-ext": "net.tls_ext_order_static_within_session",
    "go-tls-web-bot-auth": "net.web_bot_auth_invalid",
    "go-tls-madeyoureset": "net.h2_madeyoureset",
    "go-tls-web-bot-auth-replay": "net.web_bot_auth_nonce_replay",
    "ip-rotation": "net.ip_rotation_within_session",
    "mobile-emulation": "br.fingerprint_improbable",
    "camoufox-touch-incoherent": "br.pointer_touch_incoherent",
    "datacenter-origin-proxied": "net.datacenter_origin_proxied",
    "ua-rotation": "net.ua_rotation_within_session",
    "fp-rotation": "br.fingerprint_unstable_within_session",
    "trace-replay": "bh.trace_replay_within_session",
    "webgl-renderer-spoof": "br.webgl_renderer_caps_mismatch",
    "worker-proxy": "br.worker_constructor_tampered",
    "worker-proxy-fix": "br.worker_source_rewritten",
    "brave-fake-proxy": "br.brave_spoofed",
}


@pytest.mark.parametrize(("capture", "rule_id"), sorted(_LIT.items()))
def test_capture_trips_its_target_rule(capture: str, rule_id: str) -> None:
    session = Session.model_validate(json.loads((_CORPUS / f"{capture}.json").read_text()))
    verdict = Detector().score(session)
    fired = {c.rule_id for c in verdict.contradictions}
    assert rule_id in fired, f"{capture} no longer trips {rule_id} (fired: {sorted(fired)})"
    assert verdict.label.value == "bot"


def test_web_bot_auth_replay_is_not_allow_listed() -> None:
    # G32's whole point: a captured-credential replay carries a GENUINE signature, so the session also emits
    # web_bot_auth_verified (req 1 of the capture) — yet the reused nonce (req 2) must WITHHOLD the verified
    # allow-list and convict. The capture must trip net.web_bot_auth_nonce_replay and label bot, NOT verified.
    session = Session.model_validate(json.loads((_CORPUS / "go-tls-web-bot-auth-replay.json").read_text()))
    g = session.signals
    kinds = {s.kind for grp in (g.network, g.browser, g.behavioral, g.reputation) for s in grp}
    assert "web_bot_auth_verified" in kinds, "the capture should carry a genuine verified signature (req 1)"
    verdict = Detector().score(session)
    fired = {c.rule_id for c in verdict.contradictions}
    assert "net.web_bot_auth_nonce_replay" in fired
    assert verdict.label.value == "bot"  # the verified marker did NOT allow-list it


def test_madeyoureset_evades_rapid_reset() -> None:
    # G26's whole point: MadeYouReset (CVE-2025-8671) coerces server resets WITHOUT a client RST_STREAM, so
    # it slips past the rapid-reset rung (CVE-2023-44487). The live capture must trip net.h2_madeyoureset
    # while net.h2_rapid_reset stays SILENT — proving the new rung closes the exact gap the attack opened.
    session = Session.model_validate(json.loads((_CORPUS / "go-tls-madeyoureset.json").read_text()))
    fired = {c.rule_id for c in Detector().score(session).contradictions}
    assert "net.h2_madeyoureset" in fired
    assert "net.h2_rapid_reset" not in fired
