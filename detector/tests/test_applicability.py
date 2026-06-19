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
