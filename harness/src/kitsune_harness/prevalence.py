# harness/prevalence — build a prevalence prior from a fingerprint corpus (the detector scores against it).
# The pure likelihood primitives are imported from the detector (the canonical source); this adds the builder.

"""Prevalence (likelihood) model — the harness-side BUILDER.

Coherence rules catch hard *contradictions*; prevalence catches *soft improbability* — a fingerprint whose
every field is individually valid and mutually consistent (no contradiction) yet whose *combination* is
one no real user has (the BrowserForge/randomizer attack). The harness BUILDS a prior from a fingerprint
corpus; the detector SCORES a live session against it. The deep-tail score is the tell.

The pure primitives — ``FACTORS``, ``gpu_family``, ``screen_bucket``, ``cores_bucket``, ``log_prevalence``
— are the DETECTOR's (``kitsune_detector.prevalence``, imported below), so the builder and the scorer can
never hand-drift. This module adds only the two harness-specific pieces: ``features_from_fingerprint`` (read
the feature vector out of a browserforge/corpus fingerprint dict) and ``build_prior`` (count the corpus into
conditional-frequency tables). The prior is browserforge-built, so prevalence is a **corroborating** signal;
the SCREEN factor is bucketed because exact ``WxH`` missed 13-46% of real desktop resolutions vs Intoli —
see docs/prevalence-model.md for the over-leverage caveat and the cross-source check.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

# The pure likelihood primitives are the detector's (harness→detector is the sanctioned direction) — imported
# here so ``build_prior`` and the detector's scorer share ONE implementation and can never drift.
from kitsune_detector.prevalence import (
    FACTORS as _FACTORS,
)
from kitsune_detector.prevalence import (
    cores_bucket,
    gpu_family,
    log_prevalence,
    screen_bucket,
)

__all__ = [
    "Features",
    "build_prior",
    "cores_bucket",
    "features_from_fingerprint",
    "gpu_family",
    "log_prevalence",
    "screen_bucket",
]

# The fields whose JOINT distribution is modelled. Each is individually valid; the rarity is in the combo.
Features = dict[str, Any]


def features_from_fingerprint(fp: dict[str, Any]) -> Features:
    """Extract the prevalence features from a fingerprint dict (the shape calibration reads)."""
    nav = fp.get("navigator", {})
    scr = fp.get("screen", {})
    vc = fp.get("videoCard") or {}
    ua = str(nav.get("userAgent", ""))
    plat = (
        "Windows"
        if "Windows" in ua
        else "macOS"
        if re.search(r"Macintosh|Mac OS X", ua)
        else "Android"
        if "Android" in ua
        else "Linux"
        if "Linux" in ua
        else "?"
    )
    return {
        "plat": plat,
        "gpu": gpu_family(str(vc.get("renderer", ""))),
        "screen": screen_bucket(int(scr.get("width", 0) or 0), int(scr.get("height", 0) or 0)),
        "color": scr.get("colorDepth"),
        "cores": cores_bucket(nav.get("hardwareConcurrency")),
    }


def build_prior(features_list: list[Features]) -> dict[str, dict[str, dict[str, float]]]:
    """Build conditional-frequency tables for each modelled factor from a list of real fingerprints."""
    prior: dict[str, dict[str, dict[str, float]]] = {}
    for field, given in _FACTORS:
        buckets: dict[str, Counter[str]] = defaultdict(Counter)
        for f in features_list:
            buckets[str(f.get(given)) if given else "_"][str(f.get(field))] += 1
        prior[field] = {
            g: {k: v / total for k, v in c.items()} for g, c in buckets.items() if (total := sum(c.values()))
        }
    return prior
