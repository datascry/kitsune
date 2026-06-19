# detector/tests/test_fp_regression — locks in the convicting-rule FP audit (v0.74.x).
# Each scenario is a REAL browser whose build/config/hardware once tripped a convicting rule into `bot`;
# after the audit those signals only corroborate, so none may reach `bot` even paired with environment tells.

from __future__ import annotations

from datetime import UTC, datetime

import pytest

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


# Each case: (name, signals). The signal that used to convict is paired with 1-2 corroborating environment
# tells (no-webcam VM, no TTS voices, software WebGL) so the noisy-or score is bot-LEVEL — proving the
# regression guard is real: only the (now-removed) convicting category could have unlocked `bot`.
_REAL_BROWSER_CONFIGS = [
    # WebRTC disabled by a privacy extension / enterprise policy (v0.74.1).
    ("privacy-webrtc-off", {"webrtc_unavailable": True, "media_devices_empty": True, "voices_empty": True}),
    # uBlock Origin / AdBlock user on a VM — the broadest FP, 40%+ of users (v0.74.7).
    ("adblock-user", {"adblock_present": True, "media_devices_empty": True, "voices_empty": True}),
    # Open-source Chromium (ungoogled-chromium) lacks proprietary H.264/AAC (v0.74.3).
    ("ungoogled-chromium", {"codec_os_incoherent": True, "media_devices_empty": True, "webgl_software": True}),
    # Developer/designer with the Croscore fonts installed from Google Fonts (v0.74.2).
    ("croscore-fonts", {"font_linux_leak": True, "media_devices_empty": True, "voices_empty": True}),
    # Older/integrated GPU: drives WebGL but not WebGPU (v0.74.5).
    ("old-gpu-no-webgpu", {"webgpu_webgl_mismatch": True, "media_devices_empty": True, "voices_empty": True}),
    # Linux / legacy Chrome with native GL — renderer is not ANGLE-wrapped (v0.74.6).
    ("linux-chrome-native-gl", {"webgl_not_angle": True, "media_devices_empty": True, "webgl_software": True}),
    # Tor / Mullvad / RFP-Firefox privacy browser (v0.73.4).
    ("rfp-privacy-browser", {"rfp_browser": True, "voices_empty": True, "media_devices_empty": True}),
    # A CPU/V8 build whose Math.pow(PI,-100) ULP matched the "Firefox" value (retired v0.74.0).
    ("v8-math-ulp", {"math_engine_mismatch": True, "media_devices_empty": True, "webgl_software": True}),
]


@pytest.mark.parametrize("name,signals", _REAL_BROWSER_CONFIGS, ids=[c[0] for c in _REAL_BROWSER_CONFIGS])
def test_real_browser_config_is_never_convicted(name: str, signals: dict[str, object]) -> None:
    """A real browser distinguished only by a build/config/hardware choice must never score `bot`.

    Each of these tripped a convicting rule before the v0.74.x FP audit demoted that signal to
    corroborating-only. The conviction gate now caps them at `suspicious`: environment tells cannot unlock
    `bot` without a genuine convicting signature (a clear coherence/automation/artifact bot tell).
    """
    verdict = Detector().score(_session(**signals))
    convicting = {"coherence", "automation", "artifact"}
    fired = [c.rule_id for c in verdict.contradictions if c.category.value in convicting]
    assert verdict.label.value != "bot", f"{name} re-convicted by: {fired}"
