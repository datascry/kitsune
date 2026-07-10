# detector/vendors — vendor-profile registry: reproduce mainstream captcha token/verify PROTOCOLS vendor-neutrally.
# Maps a Kitsune coherence verdict onto each family's documented siteverify response shape (owned, not a clone).

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class VendorProfile:
    """A vendor-neutral reproduction of one captcha family's protocol, from PUBLIC docs only (score scale, token
    TTL, pass threshold) — never a vendor's code or assets.

    mode: "score" (invisible risk score) or "managed" (pass/fail challenge decision).
    scored: emit a numeric score field. inverted: the score is 1.0 = human (reCAPTCHA) vs higher = worse (hCaptcha).
    """

    name: str
    mode: str
    token_ttl_s: int
    threshold: float  # pass boundary on Kitsune's 0-1 (higher = more bot) scale
    scored: bool
    inverted: bool


PROFILES: dict[str, VendorProfile] = {
    # reCAPTCHA v3 (docs): 0.0-1.0 score, 1.0 very likely human, default action threshold 0.5, token ~120s single-use.
    "recaptcha_v3": VendorProfile("recaptcha_v3", "score", 120, 0.5, scored=True, inverted=True),
    # Cloudflare Turnstile (docs): non-interactive managed pass/fail, token 300s, {success, action, cdata,
    # metadata.ephemeral_id}.
    "turnstile": VendorProfile("turnstile", "managed", 300, 0.5, scored=False, inverted=False),
    # hCaptcha (docs): pass/fail + an enterprise `score` (malicious likelihood, higher = worse) + score_reason.
    "hcaptcha": VendorProfile("hcaptcha", "score", 120, 0.5, scored=True, inverted=False),
}


def vendor_score(profile: VendorProfile, kitsune_score: float) -> float:
    """Map Kitsune's coherence score (0-1, higher = more bot) onto the vendor's scale, clamped + 2dp."""
    s = 1.0 - kitsune_score if profile.inverted else kitsune_score
    return round(max(0.0, min(1.0, s)), 2)


def shape_siteverify(
    profile: VendorProfile, kitsune_score: float, action: str, challenge_ts: str, hostname: str, sid: str
) -> dict[str, object]:
    """Build the family-specific siteverify JSON from a verdict — the documented field shape, vendor-neutral."""
    passed = kitsune_score < profile.threshold  # coherent (not a bot) on Kitsune's scale
    out: dict[str, object] = {"success": True, "challenge_ts": challenge_ts, "hostname": hostname, "error-codes": []}
    if profile.name == "recaptcha_v3":
        # v3: success = valid token (the site gates on the SCORE, not on success). score 1.0 = human.
        out["score"] = vendor_score(profile, kitsune_score)
        out["action"] = action
    elif profile.name == "turnstile":
        out["success"] = passed  # managed pass/fail
        out["action"] = action
        out["cdata"] = ""
        out["metadata"] = {"ephemeral_id": hashlib.sha256(sid.encode()).hexdigest()[:16]}
    elif profile.name == "hcaptcha":
        out["success"] = passed
        out["score"] = vendor_score(profile, kitsune_score)  # enterprise malicious-likelihood (higher = worse)
        out["score_reason"] = [] if passed else ["coherence"]
        out["credit"] = False
    return out
