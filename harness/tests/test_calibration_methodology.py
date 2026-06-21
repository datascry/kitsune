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

from kitsune_harness.calibration import fingerprint_coherence, signals_from_fingerprint


def _fp(ua: str, platform: str, *, uad: dict | None = None) -> dict:
    return {"navigator": {"userAgent": ua, "platform": platform}, "userAgentData": uad}


def test_fingerprint_coherence_accepts_real_browsers_rejects_browserforge_artifacts() -> None:
    """The FP corpus must keep only internally-coherent real browsers (docs/calibration.md). Pins the
    exact incoherences browserforge cross-samples — they are flagged CORRECTLY by the convicting rules,
    so they are not false positives and must be excluded from the legit denominator, not chased as FPs."""
    win = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
    android = "Mozilla/5.0 (Linux; Android 14) Chrome/120.0.0.0 Mobile Safari/537.36"

    def cr(major: int) -> dict:
        return {"platform": "Windows", "fullVersionList": [{"brand": "Chromium", "version": f"{major}.0.0.0"}]}

    # coherent real browsers — accepted (Android's Linux-kernel platform under an Android UA stays coherent)
    assert fingerprint_coherence(_fp(win, "Win32", uad=cr(120))) == (True, "")
    assert fingerprint_coherence(_fp(android, "Linux armv8l", uad={"platform": "Android"})) == (True, "")
    # browserforge cross-sample artifacts — excluded with a reason tag for the report histogram
    assert fingerprint_coherence(_fp(win, "Linux x86_64", uad=cr(120))) == (False, "ua-vs-navplatform-os")
    assert fingerprint_coherence(_fp(win, "Win32", uad=cr(147))) == (False, "ua-vs-ch-version")
    hl = {"platform": "Windows", "fullVersionList": [{"brand": "HeadlessChrome", "version": "120.0.0.0"}]}
    assert fingerprint_coherence(_fp(win, "Win32", uad=hl)) == (False, "headless-brand")


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
    # (The session legitimately carries chrome_runtime_missing=True, so this assertion is non-vacuous.)
    fired = _headful_browser_layer_convictions("chrome-stable")
    assert fired.get(RuleCategory.coherence, set()) == set(), fired
    assert fired.get(RuleCategory.artifact, set()) == set(), fired
    assert fired.get(RuleCategory.automation, set()) == set(), fired
    # Also pin the v0.74.29 NETWORK-layer fix: the fixture is re-captured under the fixed edge, so the h2
    # header-order tell does NOT fire on a real Chrome fetch request. (Guards against a STALE fixture silently
    # re-introducing the FP — the pre-0.74.29 capture had h2_header_order_non_chromium baked in and tripped it.)
    capture = json.loads((_HEADFUL / "chrome-stable.json").read_text())
    signals = [Signal.model_validate(s) for group in capture["signals"].values() for s in group]
    all_fired = {c.rule_id for c in Detector().ingest_and_score(signals)[0].contradictions}
    assert "net.h2_header_order_vs_ua" not in all_fired, all_fired


def _net_layer_convictions(path: Path) -> set[str]:
    capture = json.loads(path.read_text())
    signals = [Signal.model_validate(s) for group in capture["signals"].values() for s in group]
    verdict = Detector().ingest_and_score(signals)[0]
    convicting = {RuleCategory.coherence, RuleCategory.automation, RuleCategory.artifact}
    return {c.rule_id for c in verdict.contradictions if c.rule_id.startswith("net.") and c.category in convicting}


def test_real_chromium_gecko_captures_trip_no_network_coherence_fp() -> None:
    # The NETWORK-layer counterpart of the browser-layer guards above — and the only FP check for the `net.*`
    # convicting category that browserforge is STRUCTURALLY BLIND to (it generates browser fingerprints, never
    # network signals; see the ~21-of-56 calibration-coverage note). The headful/privacy captures DO flow real
    # browser traffic through the edge, so they are the lab's only ground truth that a `net.*` coherence rule
    # does not false-fire on a real browser. Real Chromium + Gecko families (Chrome, Chromium, Edge, Firefox,
    # Brave, Mullvad) must trip ZERO net-layer convicting rules: their TLS/h2/TCP stack is the genuine browser
    # stack, coherent with their own UA. Without this, a new net.* rule that mis-reads real Chrome's h2/TLS
    # (cf. the v0.74.34 quic_pq retirement, an unvalidated-capture FP) would pass CI silently.
    # WebKit is EXCLUDED: corpus/calibration/headful/webkit.json is Playwright-WebKit on Linux, NOT real Safari —
    # it legitimately trips net.h2_unknown_vs_ua / net.tcp_os_vs_ua / net.tls_grease_vs_ua (a patched Linux stack
    # under a macOS-Safari UA), a documented known artifact (docs/calibration.md) that needs a real macOS Safari
    # to ground, not an FP to fix here.
    captures = [p for p in sorted(_HEADFUL.glob("*.json")) + sorted(_PRIVACY.glob("*.json")) if p.stem != "webkit"]
    assert captures, "no real captures found"
    for path in captures:
        fired = _net_layer_convictions(path)
        assert fired == set(), f"{path.stem}: net.* convicting rule false-fired on a real browser: {fired}"


def test_prevalence_never_flags_a_real_browser_capture() -> None:
    # Guard the prevalence single-source FP class on the REAL captures (the GPU 'other' fix, v0.74.33). Real
    # Firefox/Mullvad report UNCLASSIFIABLE WebGL renderers ("llvmpipe, or similar" / "Mozilla") that
    # browserforge under-generates, which once tripped br.fingerprint_improbable on gpu='other' ALONE — a
    # convicting-CATEGORY-blind FP (prevalence is corroborating, but it still raises the legit flag rate).
    # test_prevalence.test_unclassified_gpu_abstains... pins the abstain LOGIC on synthetic renderers; THIS
    # pins it on the actual captures, so a future prior/feature change that re-FPs a real browser fails CI.
    # browserforge / Intoli / the fresh captures are all BLIND to the unclassifiable-renderer path — only these
    # real Gecko/privacy captures exercise it, so without this guard the regression is uncatchable.
    captures = sorted(_HEADFUL.glob("*.json")) + sorted(_PRIVACY.glob("*.json"))
    assert captures, "no real captures found"
    for path in captures:
        capture = json.loads(path.read_text())
        signals = [Signal.model_validate(s) for group in capture["signals"].values() for s in group]
        fired = {c.rule_id for c in Detector().ingest_and_score(signals)[0].contradictions}
        assert "br.fingerprint_improbable" not in fired, f"{path.stem}: prevalence single-source FP regressed"


def test_real_privacy_browsers_no_coherence_or_artifact_fp() -> None:
    # Pin the privacy-browser FP fixes (v0.74.26-27) on the REAL captures — NOT covered by the chromium/firefox
    # test. Mullvad (Firefox-RFP) once tripped br.canvas_lie (RFP canvas farble) + br.engine_stack_vs_ua (modern
    # Gecko switched Error.captureStackTrace -> stackTraceLimit), and a real Brave's canvas farble must NOT trip
    # br.canvas_lie (it is engine-level = native). A privacy browser is a LEGIT user: it may trip AUTOMATION
    # (webdriver, from the geckodriver capture) but NO browser-layer coherence/artifact rule. browserforge cannot
    # model RFP/farbling, so this real-capture path is the only guard against a new canvas/RFP rule re-FPing them.
    for browser in ("brave", "mullvad"):
        capture = json.loads((_PRIVACY / f"{browser}.json").read_text())
        signals = [Signal.model_validate(s) for group in capture["signals"].values() for s in group]
        by_category: dict[RuleCategory, set[str]] = {}
        for contradiction in Detector().ingest_and_score(signals)[0].contradictions:
            if contradiction.rule_id.startswith("br."):
                by_category.setdefault(contradiction.category, set()).add(contradiction.rule_id)
        assert by_category.get(RuleCategory.coherence, set()) == set(), (browser, by_category)
        assert by_category.get(RuleCategory.artifact, set()) == set(), (browser, by_category)


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
    # Also pin the v0.74.31 NETWORK-layer fix: Firefox does NOT GREASE TLS (security.tls.grease_probability=0),
    # so net.tls_grease_vs_ua must NOT fire on a real Firefox. The fixture is re-captured under the fixed edge
    # (no tls_no_grease emitted for a Firefox UA); a stale pre-fix capture would carry it and re-introduce the FP.
    capture = json.loads((_HEADFUL / "firefox-stock.json").read_text())
    signals = [Signal.model_validate(s) for group in capture["signals"].values() for s in group]
    all_fired = {c.rule_id for c in Detector().ingest_and_score(signals)[0].contradictions}
    assert "net.tls_grease_vs_ua" not in all_fired, all_fired


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


def test_no_real_firefox_fixture_trips_tls_grease_vs_ua() -> None:
    # Systematic stale-fixture guard (v0.74.31/.32 lesson): Gecko does not GREASE its TLS/QUIC hello, so the
    # edge excludes Firefox from *_no_grease emission — but a fixture captured BEFORE that edge change bakes in
    # the old signal and re-scores as the FP. Score EVERY real-Firefox/Gecko baseline and require it clean of
    # net.tls_grease_vs_ua, so any future stale Gecko capture fails CI (not just the one a human re-captured).
    fixtures = [
        _HEADFUL / "firefox-stock.json",
        _HEADFUL / "firefox.json",
        _PRIVACY / "mullvad.json",
    ]
    for path in fixtures:
        capture = json.loads(path.read_text())
        signals = [Signal.model_validate(s) for group in capture["signals"].values() for s in group]
        fired = {c.rule_id for c in Detector().ingest_and_score(signals)[0].contradictions}
        assert "net.tls_grease_vs_ua" not in fired, f"{path.name} (stale GREASE signal?): {sorted(fired)}"


def test_mobile_ua_without_touch_is_a_coherence_conviction() -> None:
    """br.mobile_no_touch (research-radar G1, FP-Inconsistent IMC 2025): a phone UA reporting
    maxTouchPoints==0 is a desktop wearing a mobile UA — convicts; a real touch device (>0) and a desktop UA
    (out of scope) do not fire it. The device-DB-free spatial UA<->capability coherence catch."""
    iphone = (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
    )
    desktop = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36"

    def fired(ua: str, touch: int) -> set[str]:
        fp = {
            "navigator": {
                "userAgent": ua,
                "platform": "iPhone",
                "maxTouchPoints": touch,
                "vendor": "Apple Computer, Inc.",
            }
        }
        verdict = Detector().ingest_and_score(signals_from_fingerprint(fp, "s", _NOW))[0]
        return {c.rule_id for c in verdict.contradictions}

    assert "br.mobile_no_touch" in fired(iphone, 0)  # spoof: phone UA, no touch -> convict
    assert "br.mobile_no_touch" not in fired(iphone, 5)  # real iPhone (maxTouchPoints 5) -> silent
    assert "br.mobile_no_touch" not in fired(desktop, 0)  # desktop UA out of scope -> silent
