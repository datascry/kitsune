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
    # A real Tor/Mullvad/RFP-Firefox user (Gecko): rfp_browser (now environment, corroborating) + the
    # RFP-blocked canvas (canvas_noise) would previously noisy-or to bot. Now rfp_browser corroborates and the
    # farbling is dropped, so the privacy browser caps at suspicious, never bot.
    # v0.74.26: grounded on a real Mullvad, RFP also trips canvas_geometry_noise (perturbed isPointInPath)
    # and canvas_worker_vs_main (per-call canvas noise → main/Worker divergence) — all three are dropped.
    tor = _session(
        rfp_browser=True,
        canvas_noise=True,
        canvas_geometry_noise=True,
        canvas_worker_divergence=True,
        ua_engine="firefox",
    )
    verdict = Detector().score(tor)
    assert verdict.label.value != "bot"
    dropped = {"br.canvas_noise", "br.canvas_geometry_noise", "br.canvas_worker_vs_main"}
    assert dropped.isdisjoint({c.rule_id for c in verdict.contradictions})
    # rfp_browser itself remains visible as a corroborating tell, but as environment it cannot convict alone.
    assert "br.rfp_browser" in {c.rule_id for c in verdict.contradictions}
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
