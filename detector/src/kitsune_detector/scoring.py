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
from .models import Contradiction, Label, LayerScores, RuleCategory

# A `bot` conviction requires a *convicting* tell — a clear bot signature. Coherence (cross-vector
# contradiction), automation (webdriver/CDP surface) and artifact (anti-detect implementation flaw)
# are positive signatures of a bot. The corroborating categories — environment (a stripped/headless
# *capability* gap), behavioral, reputation and prevalence — also fire on legitimate diversity (a desktop
# with no webcam, a quiet user, a datacenter VPN, a real-but-statistically-rare fingerprint), so they may
# raise *suspicion* but never convict alone. ``prevalence`` is corroborating-by-design: a single-source
# likelihood prior (browserforge) must not convict a real-but-rare browser until corroborated (Tier-3).
CONVICTING_CATEGORIES = frozenset({RuleCategory.coherence, RuleCategory.automation, RuleCategory.artifact})


def noisy_or(weights: Iterable[float]) -> float:
    """Combine independent probabilities: 1 - ∏(1 - w). Empty -> 0.0."""
    return 1.0 - prod((1.0 - w) for w in weights)


def has_convicting(contradictions: Iterable[Contradiction]) -> bool:
    """True if any fired contradiction is a convicting (coherence/automation/artifact) signature."""
    return any(c.category in CONVICTING_CATEGORIES for c in contradictions)


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


def verified_agent(verified_present: bool, contradictions: Iterable[Contradiction]) -> bool:
    """Whether the session is an allow-listed, cryptographically VERIFIED agent — overriding the bot verdict.

    True when the session presented a VALID Web Bot Auth (RFC 9421) signature (network.web_bot_auth_verified)
    and no forgery tell fired. A declared agent that proves its identity with a key we hold is a known-good
    bot: the automation/coherence signals it legitimately trips (no JS, non-browser HTTP/2) should not convict
    it. This is the cryptographic counterpart of net.web_bot_auth_invalid.

    SECURITY NOTE — it is an ALLOW-LIST, only as strong as the signing key's secrecy: the lab seeds the PUBLIC
    RFC 9421 test key, so in-sandbox ANY client can mint a 'verified' agent (the demonstrated bypass — go-tls
    KS_WEBBOTAUTH=valid). Production trusts real agent directories whose private keys are secret.
    """
    return verified_present and not any(c.rule_id == "net.web_bot_auth_invalid" for c in contradictions)


def label_for(score: float, contradictions: Iterable[Contradiction] | None = None) -> Label:
    """Map a score to a label, gating `bot` on a convicting signal.

    A `bot` conviction requires both a bot-level score *and* at least one convicting contradiction —
    environment/behavioral/reputation tells corroborate up to `suspicious` but never convict alone, so
    a real-but-stripped browser (no webcam, no plugins) can no longer noisy-or its way to `bot`.
    ``contradictions=None`` (a bare threshold lookup) skips the gate for backwards compatibility.
    """
    if score >= BOT_THRESHOLD and (contradictions is None or has_convicting(contradictions)):
        return Label.bot
    if score >= SUSPICIOUS_THRESHOLD:
        return Label.suspicious
    return Label.human
