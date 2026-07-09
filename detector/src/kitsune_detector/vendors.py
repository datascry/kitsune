# detector/vendors — vendor-profile registry: reproduce mainstream captcha token/verify PROTOCOLS vendor-neutrally.
# Maps a Kitsune coherence verdict onto each family's documented siteverify response shape (owned, not a clone).

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VendorProfile:
    """A vendor-neutral reproduction of one captcha family's INVISIBLE-score protocol.

    Only the PUBLIC, documented protocol parameters are encoded (score scale, token TTL, pass threshold) — never
    any vendor's code or assets. ``inverted`` records the score convention: reCAPTCHA-style profiles report
    1.0 = very likely human, whereas Kitsune's native score is the opposite (higher = more bot).
    """

    name: str
    mode: str  # "score" = invisible, no challenge (reCAPTCHA v3 / Turnstile-managed / hCaptcha-enterprise archetype)
    token_ttl_s: int
    threshold: float
    inverted: bool


PROFILES: dict[str, VendorProfile] = {
    # reCAPTCHA v3 (public docs): 0.0-1.0 score, 1.0 very likely human, recommended default action threshold 0.5,
    # response token valid ~120s and single-use.
    "recaptcha_v3": VendorProfile(name="recaptcha_v3", mode="score", token_ttl_s=120, threshold=0.5, inverted=True),
}


def vendor_score(profile: VendorProfile, kitsune_score: float) -> float:
    """Map Kitsune's coherence score (0-1, higher = more bot) onto the vendor's score scale.

    Inverted (reCAPTCHA-style): ``1 - kitsune_score`` so 1.0 = very likely human; passed through otherwise.
    Clamped to [0,1] and rounded to 2dp to match the real siteverify's precision.
    """
    s = 1.0 - kitsune_score if profile.inverted else kitsune_score
    return round(max(0.0, min(1.0, s)), 2)
