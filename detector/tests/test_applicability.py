# detector/tests/test_applicability — per-browser N/A: Brave's by-design farbling must not convict a real user.
# A real Brave user trips canvas_noise+audio_noise (its Shields); is_brave drops them, but other tells stand.

from __future__ import annotations

from datetime import UTC, datetime

from kitsune_detector.detector import Detector
from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Layer, Session, Signal, Source

NOW = datetime(2026, 6, 19, tzinfo=UTC)


def _session(**fields: object) -> Session:
    sigs = [
        Signal(session_id="s", layer=Layer.browser, kind=k, value=v, source=Source.collector, observed_at=NOW)
        for k, v in fields.items()
    ]
    return group_signals(sigs)[0]


def test_real_brave_farbling_does_not_convict() -> None:
    # canvas_noise + audio_noise are both artifact (convicting) and noisy-or past the bot threshold.
    farbling = _session(canvas_noise=True, audio_noise=True)
    assert Detector().score(farbling).label.value == "bot"  # a Chrome-claiming farbler still convicts
    # The SAME farbling on a positively-identified Brave is its Shields feature → dropped → not a bot.
    brave = _session(canvas_noise=True, audio_noise=True, is_brave=True)
    verdict = Detector().score(brave)
    assert verdict.label.value != "bot"
    fired = {c.rule_id for c in verdict.contradictions}
    assert "br.canvas_noise" not in fired and "br.audio_noise" not in fired


def test_is_brave_does_not_shield_other_tells() -> None:
    # is_brave only excuses the farbling artifacts — a genuine automation tell on Brave still convicts.
    brave_bot = _session(canvas_noise=True, audio_noise=True, is_brave=True, webdriver=True)
    verdict = Detector().score(brave_bot)
    assert verdict.label.value == "bot"
    assert "br.webdriver_present" in {c.rule_id for c in verdict.contradictions}


def _multi(rows: list[tuple[str, str, object]]) -> list:
    """Score a multi-layer session (rows of (layer, kind, value)) through ingest+derivation."""
    sigs = [
        Signal.model_validate(
            {
                "schema_version": "0.1",
                "session_id": "s",
                "layer": layer,
                "kind": kind,
                "value": value,
                "source": "edge" if layer == "network" else "collector",
                "observed_at": f"2026-06-29T00:00:0{i % 9}Z",
            }
        )
        for i, (layer, kind, value) in enumerate(rows)
    ]
    return Detector().ingest_and_score(sigs)


def test_genuine_privacy_browser_measuretext_not_convicted() -> None:
    # br.measuretext_offscreen_vs is a CONVICTING artifact, but RFP per-context text-metric randomization makes
    # main != OffscreenCanvas on a real Mullvad/Tor. Exempted for a genuine RFP browser -> human; a Chrome-
    # claiming tool with the same divergence (no RFP/Gecko) is NOT exempted and still trips it.
    mullvad = _multi(
        [
            ("browser", "rfp_browser", True),
            ("browser", "ua_engine", "firefox"),
            ("browser", "measuretext_offscreen_divergence", True),
        ]
    )[0]
    assert mullvad.label.value == "human"
    assert "br.measuretext_offscreen_vs" not in {c.rule_id for c in mullvad.contradictions}
    faker = _multi([("browser", "ua_engine", "chromium"), ("browser", "measuretext_offscreen_divergence", True)])[0]
    assert "br.measuretext_offscreen_vs" in {c.rule_id for c in faker.contradictions}


def test_rfp_capability_gaps_and_brave_no_connection_exempted() -> None:
    # The privacy-browser capability gaps (WebGL2/TTS/WebRTC for RFP; Network Information API for Brave) are
    # by-design privacy features, dropped for the genuinely-identified browser -> human.
    mullvad = _multi(
        [
            ("browser", "rfp_browser", True),
            ("browser", "ua_engine", "firefox"),
            ("browser", "webgl2_missing", True),
            ("browser", "voices_empty", True),
            ("browser", "webrtc_unavailable", True),
        ]
    )[0]
    assert mullvad.label.value == "human", sorted(c.rule_id for c in mullvad.contradictions)
    brave = _multi(
        [("browser", "is_brave", True), ("browser", "ua_engine", "chromium"), ("browser", "chrome_no_connection", True)]
    )[0]
    assert "br.no_connection" not in {c.rule_id for c in brave.contradictions}
    # A non-Brave Chromium that lacks navigator.connection is still flagged (not a by-design Brave feature).
    chrome = _multi([("browser", "ua_engine", "chromium"), ("browser", "chrome_no_connection", True)])[0]
    assert "br.no_connection" in {c.rule_id for c in chrome.contradictions}


def test_tls_ext_order_static_gated_behind_proxy_egress() -> None:
    # net.tls_ext_order_static_within_session convicts a Chromium-JA4 session repeating one TLS extension order.
    # Behind a proxy/VPN/datacenter exit the observed handshake may be the proxy's, so it false-convicts a real
    # Brave on a VPN -> gated off. On DIRECT egress the rule still fires (a pinned template is a real tell).
    behind_vpn = _multi(
        [
            ("network", "ja4_browser_hint", "chrome"),
            ("network", "tls_ext_order", "aabbccdd"),
            ("network", "tls_ext_order", "aabbccdd"),
            ("reputation", "asn_is_datacenter", True),
        ]
    )[0]
    assert "net.tls_ext_order_static_within_session" not in {c.rule_id for c in behind_vpn.contradictions}
    direct = _multi(
        [
            ("network", "ja4_browser_hint", "chrome"),
            ("network", "tls_ext_order", "aabbccdd"),
            ("network", "tls_ext_order", "aabbccdd"),
        ]
    )[0]
    assert "net.tls_ext_order_static_within_session" in {c.rule_id for c in direct.contradictions}


def _ml_session(*, behavioral: dict[str, object], browser: dict[str, object] | None = None) -> Session:
    sigs = [
        Signal(session_id="s", layer=Layer.behavioral, kind=k, value=v, source=Source.collector, observed_at=NOW)
        for k, v in behavioral.items()
    ]
    sigs += [
        Signal(session_id="s", layer=Layer.browser, kind=k, value=v, source=Source.collector, observed_at=NOW)
        for k, v in (browser or {}).items()
    ]
    return group_signals(sigs)[0]


def test_mobile_drops_mouse_biomech_floors() -> None:
    # A near-straight, constant-velocity, no-coalescing pointer trips the mouse-biomech floors on desktop
    # (corroborating → suspicious). On a GENUINE mobile device they are mouse-calibrated N/A → dropped (G10).
    floors = {"mouse_straightness": 1.0, "mouse_velocity_cv": 0.0, "coalesced_events_absent": True}
    desktop = {c.rule_id for c in Detector().score(_ml_session(behavioral=floors)).contradictions}
    assert {"bh.path_too_straight", "bh.uniform_velocity", "bh.synthetic_no_coalesced"} <= desktop
    mobile = {
        c.rule_id for c in Detector().score(_ml_session(behavioral=floors, browser={"is_mobile": True})).contradictions
    }
    assert not ({"bh.path_too_straight", "bh.uniform_velocity", "bh.synthetic_no_coalesced"} & mobile)


def test_mobile_does_not_shield_trace_replay() -> None:
    # The device-agnostic convicting behavioral rule (record-and-replay) still fires on mobile.
    v = Detector().score(_ml_session(behavioral={"trace_replay": True}, browser={"is_mobile": True}))
    assert "bh.trace_replay_within_session" in {c.rule_id for c in v.contradictions}


def test_brave_readback_noise_is_excused() -> None:
    # readback_noise (getChannelData vs copyFromChannel divergence) is the same privacy-feature footprint as
    # canvas_noise/audio_noise — Brave's by-design audio farbling trips it, so it must also be N/A for Brave.
    brave = _session(audio_readback_noise=True, audio_noise=True, canvas_noise=True, is_brave=True)
    verdict = Detector().score(brave)
    assert verdict.label.value != "bot"
    fired = {c.rule_id for c in verdict.contradictions}
    assert "br.readback_noise" not in fired
    # An anti-detect tool perturbing the readback WITHOUT a privacy-browser identity still convicts.
    tool = _session(audio_readback_noise=True, audio_noise=True, canvas_noise=True)
    assert Detector().score(tool).label.value == "bot"
    assert "br.readback_noise" in {c.rule_id for c in Detector().score(tool).contradictions}


def test_real_rfp_browser_is_not_convicted() -> None:
    # A real Tor/Mullvad/RFP-Firefox user (Gecko): the RFP-blocked canvas (canvas_noise) + geometry/worker
    # divergence would previously noisy-or to bot. All are dropped as by-design farbling. Under the first-class
    # privacy stance, rfp_browser ITSELF (the identifier — "this is a privacy browser", not a bot tell) is also
    # dropped, so a genuine privacy browser with no other tell scores HUMAN, not merely "not bot".
    # v0.74.26: grounded on a real Mullvad, RFP also trips canvas_geometry_noise (perturbed isPointInPath)
    # and canvas_worker_vs_main (per-call canvas noise → main/Worker divergence) — all dropped.
    tor = _session(
        rfp_browser=True,
        canvas_noise=True,
        canvas_geometry_noise=True,
        canvas_worker_divergence=True,
        ua_engine="firefox",
    )
    verdict = Detector().score(tor)
    assert verdict.label.value == "human"
    dropped = {"br.canvas_noise", "br.canvas_geometry_noise", "br.canvas_worker_vs_main", "br.rfp_browser"}
    assert dropped.isdisjoint({c.rule_id for c in verdict.contradictions})
    # An RFP-faking automation is still caught by its automation tells.
    tor_bot = _session(rfp_browser=True, canvas_noise=True, ua_engine="firefox", webdriver=True)
    assert Detector().score(tor_bot).label.value == "bot"


def test_rfp_conjunction_on_chromium_is_not_honored() -> None:
    # RFP is a Firefox-only feature. A Chromium session that fakes the RFP conjunction (UTC + letterbox + 2
    # cores) to get its farbling excused is incoherent — the N/A is withheld and canvas_noise still convicts.
    fake = _session(rfp_browser=True, canvas_noise=True, audio_noise=True, ua_engine="chromium")
    verdict = Detector().score(fake)
    assert verdict.label.value == "bot"
    assert "br.canvas_noise" in {c.rule_id for c in verdict.contradictions}


def test_firefox_webgl_renderer_generalisation_is_not_an_artifact() -> None:
    # Firefox generalises the WebGL renderer ("llvmpipe, or similar") by default — a privacy feature, not a
    # spoof placeholder. A live headful FF137 trips br.webgl_renderer_artifact (an artifact/convicting rule),
    # so it must be N/A for the Gecko engine. Grounded: corpus/calibration/headful/firefox.json.
    ff = _session(webgl_renderer_artifact=True, ua_engine="firefox")
    verdict = Detector().score(ff)
    assert "br.webgl_renderer_artifact" not in {c.rule_id for c in verdict.contradictions}
    # On Chromium (which never emits the "…, or similar" format) the same signal is a genuine spoof artifact.
    chromium = _session(webgl_renderer_artifact=True, ua_engine="chromium")
    cv = Detector().score(chromium)
    assert "br.webgl_renderer_artifact" in {c.rule_id for c in cv.contradictions}
    assert cv.label.value == "bot"  # artifact (weight 0.8) convicts on Blink


def test_spoofed_brave_keeps_farbling_and_convicts() -> None:
    # A bot injecting a fake navigator.brave (non-native isBrave) to claim Brave: brave_spoofed fires AND the
    # genuineness guard withholds the farbling N/A, so canvas_noise/audio_noise still count. Doubly caught.
    fake = _session(is_brave=True, brave_spoofed=True, canvas_noise=True, audio_noise=True)
    verdict = Detector().score(fake)
    assert verdict.label.value == "bot"
    fired = {c.rule_id for c in verdict.contradictions}
    assert "br.brave_spoofed" in fired
    assert "br.canvas_noise" in fired  # not excused for a spoofed identity
