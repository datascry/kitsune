# detector/tests/test_prevalence — the likelihood model scores improbable joints and gates safely.
# A common fingerprint clears; a coherent-but-rare combination is deep in the prior's tail and fires.

from __future__ import annotations

from datetime import UTC, datetime

from kitsune_detector import prevalence
from kitsune_detector.detector import Detector
from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Label, Layer, Session, Signal, Source

NOW = datetime(2026, 6, 19, tzinfo=UTC)


def _session(**fields: object) -> Session:
    sigs = [
        Signal(session_id="s", layer=Layer.browser, kind=k, value=v, source=Source.collector, observed_at=NOW)
        for k, v in fields.items()
        if v is not None
    ]
    return group_signals(sigs)[0]


def _fp(plat: str | None, renderer: str, screen: str, color: int, cores: int) -> Session:
    return _session(
        ua_platform=plat,
        webgl_renderer=renderer,
        screen_resolution=screen,
        color_depth=color,
        hardware_concurrency=cores,
    )


def test_gpu_family_branches() -> None:
    f = prevalence._gpu_family
    assert f("ANGLE (NVIDIA, GeForce RTX 3080)") == "nvidia"
    assert f("ANGLE (Apple, Apple M2)") == "apple"
    assert f("ANGLE (Intel, Intel UHD Graphics)") == "intel"
    assert f("ANGLE (AMD, Radeon)") == "amd"
    assert f("Adreno (TM) 640") == "mobile"
    assert f("ANGLE (Google, SwiftShader)") == "swiftshader"
    # An unclassifiable renderer is UNKNOWN, not a deep-tail bucket → None so the joint abstains (the FP fix:
    # real Firefox "llvmpipe, or similar" / Mullvad-RFP "Mozilla" no longer trip br.fingerprint_improbable).
    assert f("Some Unknown GPU") is None
    assert f("llvmpipe, or similar") is None  # real Firefox software-render generalization
    assert f("Mozilla") is None  # real Mullvad / RFP renderer generalization


def test_screen_bucket() -> None:
    # Kept in sync with kitsune_harness.prevalence.screen_bucket.
    assert prevalence._screen_bucket("1920x1080") == "desktop-land"
    assert prevalence._screen_bucket("1470x956") == "laptop-land"
    assert prevalence._screen_bucket("390x844") == "mobile-port"
    assert prevalence._screen_bucket("3840x2160") == "large-land"
    assert prevalence._screen_bucket("garbage") is None and prevalence._screen_bucket("0x0") is None


def test_features_from_session() -> None:
    feats = prevalence.features_from_session(_fp("macOS", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8))
    assert feats == {"plat": "macOS", "gpu": "apple", "screen": "laptop-land", "color": 30, "cores": "5-8"}


def test_common_clears_improbable_fires() -> None:
    # a common real macOS/Apple combo is not improbable
    assert prevalence.is_improbable(_fp("macOS", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8)) is False
    # coherent fields, improbable joint: a Windows UA with an Apple GPU + a Mac screen — no real user
    assert prevalence.is_improbable(_fp("Windows", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8)) is True


def test_unclassified_gpu_abstains_real_firefox_mullvad_not_improbable() -> None:
    # FP fix (GROUNDED on real captures): an UNCLASSIFIABLE WebGL renderer is GPU-family UNKNOWN, so the joint
    # abstains rather than taking the old "other" eps-floor penalty. Real Firefox software-rendering reports
    # "llvmpipe, or similar" and Mullvad/RFP reports "Mozilla" — both map to no known family. With an otherwise
    # common Linux + small-screen + 8-core vector they must NOT fire (they did, on gpu='other', before the fix).
    assert prevalence.is_improbable(_fp("Linux", "llvmpipe, or similar", "1280x720", 24, 12)) is False
    assert prevalence.is_improbable(_fp("Linux", "Mozilla", "1280x720", 24, 4)) is False
    # The recognized-family improbable joint is unaffected — a genuinely improbable known GPU still fires.
    assert prevalence.is_improbable(_fp("Windows", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8)) is True


def test_unscoreable_sessions_never_fire() -> None:
    # missing platform/gpu → cannot score → never fire (a non-browser / no-JS session)
    assert prevalence.is_improbable(_fp(None, "ANGLE (Apple, Apple M2)", "1470x956", 30, 8)) is False
    assert prevalence.is_improbable(_fp("?", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8)) is False
    assert prevalence.is_improbable(_session(ua_platform="Windows")) is False  # no webgl_renderer


def test_partial_vector_abstains_unknown_never_fires() -> None:
    # The Windows+Apple-GPU+Mac-screen joint IS improbable with a full vector (asserted above). But the
    # committed threshold is the p1 of FULL-vector fingerprints, so a MISSING factor adds an eps floor
    # (~-9.2 nats) that masquerades as improbability. Dropping any SCORED factor (gpu/screen/cores) must
    # make the rule ABSTAIN, not convict the gap — "unknown never fires".
    assert prevalence.is_improbable(_fp("Windows", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8)) is True
    for drop in ("screen_resolution", "hardware_concurrency"):
        fields = {
            "ua_platform": "Windows",
            "webgl_renderer": "ANGLE (Apple, Apple M2)",
            "screen_resolution": "1470x956",
            "color_depth": 30,
            "hardware_concurrency": 8,
        }
        del fields[drop]
        assert prevalence.is_improbable(_session(**fields)) is False, f"fired on a vector missing {drop}"
    # color_depth is NO LONGER a scored factor (v0.74.20, dropped as a browserforge single-source artifact),
    # so a vector missing it still scores normally (and this improbable joint still fires) — not abstention.
    no_colour = {
        "ua_platform": "Windows",
        "webgl_renderer": "ANGLE (Apple, Apple M2)",
        "screen_resolution": "1470x956",
        "hardware_concurrency": 8,
    }
    assert prevalence.is_improbable(_session(**no_colour)) is True


def test_log_prevalence_orders_by_probability() -> None:
    p = prevalence._load_prior()["prior"]
    common = prevalence.features_from_session(_fp("macOS", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8))
    rare = prevalence.features_from_session(_fp("Windows", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8))
    assert prevalence.log_prevalence(common, p) > prevalence.log_prevalence(rare, p)


def test_detector_emits_prevalence_low_and_rule_fires() -> None:
    verdict = Detector().score(_fp("Windows", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8))
    assert "br.fingerprint_improbable" in {c.rule_id for c in verdict.contradictions}
    # a common fingerprint does not trip it
    clear = Detector().score(_fp("macOS", "ANGLE (Apple, Apple M2)", "1470x956", 30, 8))
    assert "br.fingerprint_improbable" not in {c.rule_id for c in clear.contradictions}


def test_prevalence_is_corroborating_never_convicts_alone() -> None:
    # A real-but-rare browser: improbable joint (prevalence_low) + a no-webcam desktop (media_devices_empty,
    # an environment tell) and NO hard coherence/automation signal. The single-source browserforge
    # prevalence rule must NOT convict it — the bot conviction gate requires a non-prevalence signal.
    sess = _session(
        ua_platform="Windows",
        webgl_renderer="ANGLE (Apple, Apple M2)",
        screen_resolution="1470x956",
        color_depth=30,
        hardware_concurrency=8,
        media_devices_empty=True,
    )
    verdict = Detector().score(sess)
    fired = {c.rule_id for c in verdict.contradictions}
    assert "br.fingerprint_improbable" in fired and "br.media_devices_empty" in fired
    assert verdict.score >= 0.65  # noisy-or crosses the bot threshold...
    assert verdict.label is not Label.bot  # ...but prevalence cannot convict alone → capped at suspicious
    prevalence_cat = next(c.category for c in verdict.contradictions if c.rule_id == "br.fingerprint_improbable")
    assert prevalence_cat.value == "prevalence"


def test_committed_threshold_is_cross_source_conservative() -> None:
    # Guard the v0.74.24 FP fix: the committed threshold must stay CONSERVATIVE (cross-source-calibrated),
    # not the browserforge self-p1 (~-7.73) which over-flags an independent dataset (fpgen) ~5x. A regen that
    # reverts to the self-p1 (build without fpgen) would lift it back above this bound and fail here.
    import json

    from kitsune_detector.prevalence import _DATA

    prior = json.loads((_DATA / "prevalence_prior.json").read_text())
    assert prior["threshold"] <= -8.0, (
        f"prevalence threshold {prior['threshold']} is shallower than the cross-source-conservative bound — "
        "it over-flags independent data; rebuild with fpgen (see browserforge_corpus.build_prior_file)"
    )
    assert prior.get("threshold_calibration", "").startswith("cross-source")
