# harness/prevalence — score how probable a fingerprint's joint field combination is (likelihood model).
# Catches coherent-but-improbable fingerprints (the randomizer attack) that the contradiction rules miss.

"""Prevalence (likelihood) model.

Coherence rules catch hard *contradictions*; this catches *soft improbability* — a fingerprint whose
every field is individually valid and mutually consistent (no contradiction) yet whose *combination* is
one no real user has (the BrowserForge/randomizer attack). It scores the log-prevalence of a fingerprint's
key field combination under a real-distribution prior; a deep-tail score is the tell.

Pure: ``build_prior`` and ``log_prevalence`` take plain feature dicts, so the prior can be built from any
source (browserforge today; Tier-3 real traffic later). The prior is a single source for now, so this is a
**corroborating** signal — see docs/prevalence-model.md for the over-leverage caveat.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from typing import Any

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
    r = str(vc.get("renderer", "")).lower()
    gpu = (
        "nvidia"
        if re.search(r"nvidia|geforce|rtx|gtx", r)
        else "apple"
        if re.search(r"apple|metal|\bm[123]\b", r)
        else "intel"
        if re.search(r"intel|iris|uhd|hd graphics", r)
        else "amd"
        if re.search(r"\bamd\b|radeon", r)
        else "mobile"
        if re.search(r"adreno|mali|powervr", r)
        else "swiftshader"
        if "swiftshader" in r
        else "other"
    )
    return {
        "plat": plat,
        "gpu": gpu,
        "screen": f"{scr.get('width')}x{scr.get('height')}",
        "color": scr.get("colorDepth"),
        "cores": nav.get("hardwareConcurrency"),
    }


# Each modelled factor: (field, conditioned-on). ``None`` = marginal (unconditioned).
_FACTORS: tuple[tuple[str, str | None], ...] = (
    ("gpu", "plat"),
    ("screen", "plat"),
    ("color", "plat"),
    ("cores", None),
)


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


def log_prevalence(features: Features, prior: dict[str, dict[str, dict[str, float]]], *, eps: float = 1e-4) -> float:
    """Sum of log conditional probabilities — low (deep-negative) means an improbable joint combination."""
    total = 0.0
    for field, given in _FACTORS:
        key = str(features.get(given)) if given else "_"
        table = prior.get(field, {}).get(key, {})
        total += math.log(table.get(str(features.get(field)), 0.0) + eps)
    return total
