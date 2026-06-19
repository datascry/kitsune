# detector/prevalence — score how probable a session's joint fingerprint is under a real-traffic prior.
# Catches coherent-but-improbable fingerprints (the randomizer attack) the contradiction rules miss.

"""Prevalence (likelihood) scoring at score time.

Coherence rules catch hard contradictions; this scores *soft improbability* — a fingerprint whose every
field is valid and consistent (no contradiction) yet whose combination is one no real user has. It reads
the platform/gpu/screen/colour/cores the collector emits, scores the log-prevalence under a committed
prior (``data/prevalence_prior.json``), and (below the prior's conservative p1 threshold) emits
``browser.prevalence_low``. Corroborating-only: the prior is a single source (browserforge), so the rule
is experimental + low weight until the prior is corroborated against Tier-3 real traffic
(docs/prevalence-model.md). Field extraction is kept in sync with ``kitsune_harness.prevalence``.
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from .models import MISSING, Layer, Session

_DATA = Path(__file__).parent / "data"
_FACTORS: tuple[tuple[str, str | None], ...] = (("gpu", "plat"), ("screen", "plat"), ("color", "plat"), ("cores", None))


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


def _v(session: Session, kind: str) -> Any:
    val = session.value(Layer.browser, kind)
    return None if val is MISSING else val


def features_from_session(session: Session) -> dict[str, Any]:
    """Extract the prevalence features from a session's browser signals (mirrors the collector's values)."""
    renderer = _v(session, "webgl_renderer")
    return {
        "plat": _v(session, "ua_platform"),
        "gpu": _gpu_family(str(renderer)) if renderer else None,
        "screen": _v(session, "screen_resolution"),
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


def is_improbable(session: Session) -> bool:
    """True iff the session's coherent fingerprint is deep in the improbable tail of the real-traffic prior."""
    feats = features_from_session(session)
    if not feats["plat"] or feats["plat"] == "?" or not feats["gpu"]:
        return False  # cannot score without the core fields — never fire on a non-browser/no-JS session
    p = _load_prior()
    return log_prevalence(feats, p["prior"]) < float(p["threshold"])
