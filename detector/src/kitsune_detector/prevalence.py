# detector/prevalence — score how probable a session's joint fingerprint is under a real-traffic prior.
# Catches coherent-but-improbable fingerprints (the randomizer attack) the contradiction rules miss.

"""Prevalence (likelihood) scoring at score time.

Coherence rules catch hard contradictions; this scores *soft improbability* — a fingerprint whose every
field is valid and consistent (no contradiction) yet whose combination is one no real user has. It reads
the platform/gpu/screen/colour/cores the collector emits, scores the log-prevalence under a committed
prior (``data/prevalence_prior.json``), and (below the prior's conservative p1 threshold) emits
``browser.prevalence_low``. Corroborating-only: the prior is browserforge-built, so the rule is
experimental + low weight. The SCREEN factor is cross-validated against the Intoli real-traffic source —
exact ``WxH`` missed 13-46% of real desktop resolutions (a circular single-source FP), so screen is scored
as a coarse (size-class, orientation) bucket whose real-traffic miss is ~0%; gpu/colour/cores remain
single-source pending Tier-3 (docs/prevalence-model.md). Field extraction (incl. the screen bucket) is kept
in sync with ``kitsune_harness.prevalence``.
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from .models import MISSING, Layer, Session

_DATA = Path(__file__).parent / "data"
# v0.74.20: the COLOUR factor (color_depth given platform) was DROPPED — a circular single-source FP.
# color_depth is a DISPLAY property (24 = sRGB, 30 = HDR), OS-independent — every real browser reports 24
# regardless of platform (grounded: the headful Chromium/Firefox/WebKit captures all report 24). But
# browserforge GENERATES color_depth=32 for Windows at 93%, so a real Windows user (24) took a ~-3 log
# penalty the calibration could never see (browserforge scores its own 32s against a 32-heavy prior).
# Conditioning a display property on the OS is unsound and the prior is uncorroborable (Intoli lacks
# color_depth), so the factor is removed rather than trusted single-source. gpu/screen/cores remain.
_FACTORS: tuple[tuple[str, str | None], ...] = (("gpu", "plat"), ("screen", "plat"), ("cores", None))


def _gpu_family(renderer: str) -> str:
    r = renderer.lower()
    if re.search(r"nvidia|geforce|rtx|gtx", r):
        return "nvidia"
    if re.search(r"apple|metal|\bm[123]\b", r):
        return "apple"
    if re.search(r"intel|iris|uhd|hd graphics", r):
        return "intel"
    if re.search(r"\bamd\b|radeon", r):
        return "amd"
    if re.search(r"adreno|mali|powervr", r):
        return "mobile"
    if "swiftshader" in r:
        return "swiftshader"
    return "other"


def _screen_bucket(res: str) -> str | None:
    """Coarse, cross-source-robust screen feature: (size-class, orientation) from a "WxH" resolution.

    Kept in sync with ``kitsune_harness.prevalence.screen_bucket``. The exact resolution is a single-source
    FP landmine — the browserforge prior misses 13-46% of REAL desktop resolutions (verified vs the Intoli
    real-traffic source; see docs/prevalence-model.md) — so prevalence scores the coarse bucket instead.
    """
    m = re.match(r"^\s*(\d+)\s*x\s*(\d+)\s*$", res)
    if not m:
        return None
    w, h = int(m.group(1)), int(m.group(2))
    if w <= 0 or h <= 0:
        return None
    hi = max(w, h)
    orient = "port" if h >= w else "land"
    cls = (
        "mobile"
        if hi <= 960
        else "small"
        if hi <= 1366
        else "laptop"
        if hi <= 1680
        else "desktop"
        if hi <= 2560
        else "large"
    )
    return f"{cls}-{orient}"


def _v(session: Session, kind: str) -> Any:
    val = session.value(Layer.browser, kind)
    return None if val is MISSING else val


def features_from_session(session: Session) -> dict[str, Any]:
    """Extract the prevalence features from a session's browser signals (mirrors the collector's values)."""
    renderer = _v(session, "webgl_renderer")
    res = _v(session, "screen_resolution")
    return {
        "plat": _v(session, "ua_platform"),
        "gpu": _gpu_family(str(renderer)) if renderer else None,
        "screen": _screen_bucket(str(res)) if res else None,
        "color": _v(session, "color_depth"),
        "cores": _v(session, "hardware_concurrency"),
    }


def log_prevalence(features: dict[str, Any], prior: dict[str, Any], *, eps: float = 1e-4) -> float:
    total = 0.0
    for field, given in _FACTORS:
        key = str(features.get(given)) if given else "_"
        table = prior.get(field, {}).get(key, {})
        total += math.log(table.get(str(features.get(field)), 0.0) + eps)
    return total


_PRIOR: dict[str, Any] | None = None


def _load_prior() -> dict[str, Any]:
    global _PRIOR
    if _PRIOR is None:
        _PRIOR = json.loads((_DATA / "prevalence_prior.json").read_text())
    return _PRIOR


_SCORED = ("gpu", "screen", "cores")


def is_improbable(session: Session) -> bool:
    """True iff the session's coherent fingerprint is deep in the improbable tail of the real-traffic prior.

    "Unknown never fires": the committed threshold is the 1st percentile of *full-vector* browserforge
    fingerprints, so the joint is only meaningful when the whole feature vector was actually observed. A
    MISSING factor adds an ``eps`` floor (~-9.2 nats each) to ``log_prevalence`` — so a session lacking
    screen + colour alone sinks ~-18 below the threshold and trips on *absence*, not improbability (an
    absence-as-improbability FP). When any modelled factor is unobserved we cannot assess the joint, so we
    abstain rather than convict the gap.
    """
    feats = features_from_session(session)
    if not feats["plat"] or feats["plat"] == "?":
        return False  # no platform anchor — cannot condition the joint (non-browser / no-JS session)
    if any(feats.get(f) is None for f in _SCORED):
        return False  # partial vector — abstain (unknown never fires)
    p = _load_prior()
    return log_prevalence(feats, p["prior"]) < float(p["threshold"])
