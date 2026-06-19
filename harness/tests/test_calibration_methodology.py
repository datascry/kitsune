# tests/test_calibration_methodology — lock the Tier-2 proof: the mapper invents no FALSE coherence/artifact.
# Scores the real-engine references through signals_from_fingerprint and pins which convicting rules may fire.

"""Methodology regression guard for the FP gate (docs/calibration.md "Second data source").

The calibration FP numbers are only trustworthy if ``signals_from_fingerprint`` reproduces what a REAL
browser emits — not artefacts of the mapper. ``corpus/calibration/engines/`` holds real (headless,
Playwright-captured) Chromium/Firefox/WebKit fingerprints; mapping + scoring them must show that the
*coherence* and *artifact* convicting categories — the ones that actually convict — never false-fire on a
real engine's own internally-coherent fingerprint. The headless captures legitimately trip *automation*
(`webdriver_present`/`ch_he_headless`) and *environment* (container `media_devices_empty` etc.) tells; those
are expected and are NOT the methodology question.

This test pins the documented Tier-2 result so a future mapper/rule change cannot silently reintroduce a
single-source FP: Chromium/Firefox produce ZERO coherence+artifact contradictions; the only coherence fire
anywhere is WebKit's `br.navplatform_vs_ua`, the known Playwright-on-Linux (Mac UA + Linux host platform)
quirk — not real Safari — and `br.webgl_not_angle` (a refuted browserforge artifact) fires on none.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kitsune_detector.detector import Detector
from kitsune_detector.models import RuleCategory, Signal

from kitsune_harness.calibration import signals_from_fingerprint

_NOW = datetime(2026, 6, 19, tzinfo=UTC)
_CALIB = Path(__file__).resolve().parents[2] / "corpus" / "calibration"
_ENGINES = _CALIB / "engines"
_HEADFUL = _CALIB / "headful"
_PRIVACY = _CALIB / "privacy"


def _fired_by_category(engine: str) -> dict[RuleCategory, set[str]]:
    fingerprint = json.loads((_ENGINES / f"{engine}.json").read_text())
    signals = signals_from_fingerprint(fingerprint, engine, _NOW)
    verdict = Detector().ingest_and_score(signals)[0]
    by_category: dict[RuleCategory, set[str]] = {}
    for contradiction in verdict.contradictions:
        by_category.setdefault(contradiction.category, set()).add(contradiction.rule_id)
    return by_category


def test_real_engines_never_false_fire_a_coherence_or_artifact_rule() -> None:
    # Chromium and Firefox are internally coherent: no convicting coherence/artifact rule may fire.
    for engine in ("chromium", "firefox"):
        fired = _fired_by_category(engine)
        assert fired.get(RuleCategory.coherence, set()) == set(), engine
        assert fired.get(RuleCategory.artifact, set()) == set(), engine


def test_webkit_only_coherence_fire_is_the_known_playwright_linux_quirk() -> None:
    # The single documented exception: Playwright WebKit is a Linux host wearing a macOS Safari UA, so
    # navigator.platform (Linux) contradicts the UA platform (Mac). Real Safari is MacIntel — coherent.
    fired = _fired_by_category("webkit")
    assert fired.get(RuleCategory.coherence, set()) == {"br.navplatform_vs_ua"}
    assert fired.get(RuleCategory.artifact, set()) == set()


def test_webgl_not_angle_is_a_refuted_browserforge_artifact_on_no_real_engine() -> None:
    for engine in ("chromium", "firefox", "webkit"):
        fired = _fired_by_category(engine)
        fired_rules = set().union(*fired.values()) if fired else set()
        assert "br.webgl_not_angle" not in fired_rules, engine


def test_headless_engine_references_still_convict_via_automation() -> None:
    # Sanity: the references ARE headless/automated and must score bot via the automation category — the
    # methodology check is about coherence/artifact precision, not about these (correct) automation tells.
    for engine in ("chromium", "firefox", "webkit"):
        fired = _fired_by_category(engine)
        assert fired.get(RuleCategory.automation, set()), engine


# --- The stronger, mapper-FREE guard: score the REAL headful captures (collector ground truth). ----------
# corpus/calibration/headful/ holds clean headful (xvfb) Chromium/Firefox/WebKit captures driven through the
# genuine collector — the closest thing the lab has to a real user's browser. This bypasses the fingerprint
# mapper entirely and asserts the FP-critical invariant directly on real signals: no BROWSER-layer (br.*)
# fingerprint coherence/artifact rule may false-fire on a real browser. The NETWORK-layer (net.*) coherence
# fires on Playwright Firefox/WebKit (TLS/QUIC GREASE, h2 order, tcp_os) are out of scope — those are
# PATCHED-build network-stack artifacts, not real Firefox/Safari (documented in docs/calibration.md); acting
# on them would need a non-Playwright real-Firefox/Safari capture (the "no single questionable source" rule).


def _headful_browser_layer_convictions(engine: str) -> dict[RuleCategory, set[str]]:
    capture = json.loads((_HEADFUL / f"{engine}.json").read_text())
    signals = [Signal.model_validate(s) for group in capture["signals"].values() for s in group]
    verdict = Detector().ingest_and_score(signals)[0]
    out: dict[RuleCategory, set[str]] = {}
    for contradiction in verdict.contradictions:
        if contradiction.rule_id.startswith("br."):
            out.setdefault(contradiction.category, set()).add(contradiction.rule_id)
    return out


def test_real_headful_chromium_firefox_no_browser_coherence_or_artifact_fp() -> None:
    # The strongest FP-safety statement: real headful browsers trip no browser-layer fingerprint
    # coherence/artifact rule. (Automation/environment/behavioural tells from the driver + container are
    # expected and out of scope.) Chromium's Playwright network stack is representative; it is fully clean.
    for engine in ("chromium", "firefox"):
        fired = _headful_browser_layer_convictions(engine)
        assert fired.get(RuleCategory.coherence, set()) == set(), engine
        assert fired.get(RuleCategory.artifact, set()) == set(), engine


def test_real_nonautomated_chrome_trips_no_browser_layer_conviction() -> None:
    # corpus/calibration/headful/chrome-stable.json: REAL Google Chrome 149, MANUALLY launched (NOT via
    # Playwright automation, connected over CDP) so navigator.webdriver === false — a genuine human-Chrome
    # baseline, the most common real browser. v0.74.28 grounds the br.chrome_runtime_missing RETIREMENT:
    # modern Chrome removed chrome.runtime from normal pages (~v106), so window.chrome-without-runtime no
    # longer distinguishes headless from a real human's Chrome — the rule convicted EVERY real Chrome user.
    # A real, non-automated Chrome must trip NO browser-layer convicting rule (coherence/artifact/AUTOMATION).
    # (The session legitimately carries chrome_runtime_missing=True, so this assertion is non-vacuous; the
    # network-layer h2/QUIC GREASE fires are the documented container path artifacts, out of scope here.)
    fired = _headful_browser_layer_convictions("chrome-stable")
    assert fired.get(RuleCategory.coherence, set()) == set(), fired
    assert fired.get(RuleCategory.artifact, set()) == set(), fired
    assert fired.get(RuleCategory.automation, set()) == set(), fired


def test_real_edge_chromium_family_not_a_tls_or_h2_browser_contradiction() -> None:
    # corpus/calibration/headful/msedge.json: REAL Microsoft Edge 149. Edge is Chromium, so its TLS/HTTP-2
    # stack hints 'chrome' while ua_browser is 'edge'. v0.74.30 (not_equal_browser predicate): a literal
    # not_equal convicted every real Edge on net.tls_vs_ua_browser + net.h2_vs_ua_browser; the family-aware
    # predicate collapses the Chromium family so those do NOT fire. Non-vacuous: the fixture carries the
    # ja4/h2 hint 'chrome' vs ua_browser 'edge' mismatch inputs.
    capture = json.loads((_HEADFUL / "msedge.json").read_text())
    browser = {s["kind"]: s["value"] for s in capture["signals"]["browser"]}
    network = {s["kind"]: s["value"] for s in capture["signals"]["network"]}
    assert browser.get("ua_browser") == "edge"
    assert network.get("ja4_browser_hint") == "chrome" and network.get("h2_browser_hint") == "chrome"

    signals = [Signal.model_validate(s) for group in capture["signals"].values() for s in group]
    fired = {c.rule_id for c in Detector().ingest_and_score(signals)[0].contradictions}
    assert fired.isdisjoint({"net.tls_vs_ua_browser", "net.h2_vs_ua_browser"}), fired


def test_real_stock_firefox_152_no_browser_coherence_or_artifact_fp() -> None:
    # Stock Firefox 152 (geckodriver, NOT Playwright's Juggler build — the strongest real-Firefox source).
    # v0.74.27 grounds the engine_stack_vs_ua FP fix: Firefox added Error.captureStackTrace natively in v122,
    # so the rule switched to the still-V8-exclusive Error.stackTraceLimit. A real modern Firefox must trip no
    # br.* coherence/artifact rule — in particular NOT engine_stack_vs_ua (the FP this capture exposed).
    fired = _headful_browser_layer_convictions("firefox-stock")
    assert fired.get(RuleCategory.coherence, set()) == set(), fired
    assert fired.get(RuleCategory.artifact, set()) == set(), fired


def test_real_headful_webkit_only_browser_coherence_is_the_navplatform_quirk() -> None:
    # Real headful WebKit's only browser-layer coherence fire is the same Playwright-on-Linux Mac-UA quirk
    # (navigator.platform=Linux vs a macOS Safari UA) — not real Safari, which is MacIntel and coherent.
    fired = _headful_browser_layer_convictions("webkit")
    assert fired.get(RuleCategory.coherence, set()) == {"br.navplatform_vs_ua"}
    assert fired.get(RuleCategory.artifact, set()) == set()


# --- Privacy-browser FP grounding: a real Brave's BY-DESIGN farbling must not convict it. -----------------
# corpus/calibration/privacy/brave.json is a REAL Brave (default Shields) capture through the live collector.
# Privacy/hardened browsers (Brave, Tor, Mullvad, LibreWolf) deliberately farble canvas/audio — a surface
# browserforge/fpgen/Intoli/SapiMouse all miss. This pins the FP-safety question a privacy-browser user
# raises: farbling is NOT a conviction. (The capture is Playwright-driven, so it legitimately trips
# automation/environment/behavioural tells from the driver + container — those are out of scope here.)
def test_real_brave_farbling_does_not_trip_the_canvas_or_audio_spoof_rules() -> None:
    capture = json.loads((_PRIVACY / "brave.json").read_text())
    browser = {s["kind"]: s["value"] for s in capture["signals"]["browser"]}
    # The capture is only meaningful if Brave actually farbled — else the assertion below is vacuous.
    assert browser.get("is_brave") is True
    assert browser.get("canvas_noise") is True  # Brave perturbs canvas readback by default
    assert browser.get("audio_readback_noise") is True  # ...and audio readback
    assert "canvas_lie" not in browser  # engine-level farbling keeps toDataURL NATIVE — no getter-override lie

    signals = [Signal.model_validate(s) for group in capture["signals"].values() for s in group]
    fired = {c.rule_id for c in Detector().ingest_and_score(signals)[0].contradictions}
    # The privacy-feature-targeted rules must NOT convict a real privacy browser on its privacy feature:
    # canvas_lie stays silent (native toString), and is_brave drops audio_noise/readback_noise (applicability).
    assert fired.isdisjoint({"br.canvas_lie", "br.audio_noise", "br.readback_noise"}), fired


def test_real_mullvad_rfp_farbling_does_not_trip_the_canvas_spoof_rules() -> None:
    # corpus/calibration/privacy/mullvad.json is a REAL Mullvad Browser (Firefox-RFP) capture (geckodriver).
    # v0.74.26: RFP perturbs the canvas readback AND the canvas geometry AND diverges main-vs-Worker canvas,
    # tripping three CONVICTING rules; the fix identifies Mullvad as rfp_browser (via the "Mozilla" WebGL tell,
    # since modern RFP no longer clamps cores) and drops all three. Pins that a real Mullvad is not convicted
    # on its by-design farbling. (Driver tells — webdriver — and network-stack GREASE are out of scope.)
    capture = json.loads((_PRIVACY / "mullvad.json").read_text())
    browser = {s["kind"]: s["value"] for s in capture["signals"]["browser"]}
    assert browser.get("rfp_browser") is True  # modern Mullvad is now identified (was the bug)
    assert browser.get("ua_engine") == "firefox"
    assert browser.get("canvas_noise") is True  # RFP really does farble — assertion below is not vacuous
    assert browser.get("canvas_geometry_noise") is True
    assert browser.get("canvas_worker_divergence") is True

    signals = [Signal.model_validate(s) for group in capture["signals"].values() for s in group]
    fired = {c.rule_id for c in Detector().ingest_and_score(signals)[0].contradictions}
    assert fired.isdisjoint({"br.canvas_noise", "br.canvas_geometry_noise", "br.canvas_worker_vs_main"}), fired
