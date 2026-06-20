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
}


@pytest.mark.parametrize(("capture", "rule_id"), sorted(_LIT.items()))
def test_capture_trips_its_target_rule(capture: str, rule_id: str) -> None:
    session = Session.model_validate(json.loads((_CORPUS / f"{capture}.json").read_text()))
    verdict = Detector().score(session)
    fired = {c.rule_id for c in verdict.contradictions}
    assert rule_id in fired, f"{capture} no longer trips {rule_id} (fired: {sorted(fired)})"
    assert verdict.label.value == "bot"
