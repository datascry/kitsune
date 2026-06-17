# detector/scoring — turn contradictions into an explainable verdict.
# Transparent noisy-or; cross-layer (incoherence) contradictions are amplified.

"""Turn a list of contradictions into a verdict — transparently.

Scoring is deliberately simple and explainable: every score is a *noisy-or* combination of
contradiction weights, so it is monotonic (more/*stronger* contradictions never lower a score) and
fully traceable back to the evidence. Cross-layer contradictions are amplified by
``INCOHERENCE_WEIGHT`` — the mechanical expression of Kitsune's thesis.
"""

from __future__ import annotations

from collections.abc import Iterable
from math import prod

from .config import BOT_THRESHOLD, INCOHERENCE_WEIGHT, SUSPICIOUS_THRESHOLD
from .models import Contradiction, Label, LayerScores


def noisy_or(weights: Iterable[float]) -> float:
    """Combine independent probabilities: 1 - ∏(1 - w). Empty -> 0.0."""
    return 1.0 - prod((1.0 - w) for w in weights)


def _effective_weight(c: Contradiction) -> float:
    """Cross-layer contradictions count for more — incoherence is the differentiator."""
    if c.is_cross_layer:
        return min(1.0, c.weight * (1.0 + INCOHERENCE_WEIGHT))
    return c.weight


def layer_scores(contradictions: list[Contradiction]) -> LayerScores:
    """Per-layer score = noisy-or of the weights of contradictions touching that layer."""
    buckets: dict[str, list[float]] = {
        "network": [],
        "browser": [],
        "behavioral": [],
        "reputation": [],
    }
    for c in contradictions:
        for layer in set(c.layers):
            buckets[layer.value].append(c.weight)
    return LayerScores(**{name: noisy_or(weights) for name, weights in buckets.items()})


def incoherence_score(contradictions: list[Contradiction]) -> float:
    """Noisy-or over only the *cross-layer* contradictions — the thesis metric."""
    return noisy_or(c.weight for c in contradictions if c.is_cross_layer)


def final_score(contradictions: list[Contradiction]) -> float:
    """Noisy-or over every contradiction's *effective* (incoherence-amplified) weight."""
    return noisy_or(_effective_weight(c) for c in contradictions)


def label_for(score: float) -> Label:
    if score >= BOT_THRESHOLD:
        return Label.bot
    if score >= SUSPICIOUS_THRESHOLD:
        return Label.suspicious
    return Label.human
