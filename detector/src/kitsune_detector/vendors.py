# detector/vendors — vendor-profile registry: reproduce mainstream captcha token/verify PROTOCOLS vendor-neutrally.
# Maps a Kitsune coherence verdict onto each family's documented siteverify response shape (owned, not a clone).

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class VendorProfile:
    """A vendor-neutral reproduction of one captcha family's protocol, from PUBLIC docs only (score scale, token
    TTL, pass threshold) — never a vendor's code or assets.

    mode: "score" (invisible risk score), "managed" (pass/fail decision), or "challenge" (pre-check that
    escalates to an interactive gate when suspicious — see challenge_gate).
    scored: emit a numeric score field. inverted: the score is 1.0 = human (reCAPTCHA) vs higher = worse (hCaptcha).
    """

    name: str
    mode: str
    token_ttl_s: int
    threshold: float  # pass boundary on Kitsune's 0-1 (higher = more bot) scale
    scored: bool
    inverted: bool
    # challenge-ladder: a "challenge" family runs the invisible risk pre-check and, when the verdict is suspicious
    # (score >= threshold), ESCALATES to an interactive gate instead of silently passing (reCAPTCHA v2 grid, Arkose
    # game). Empty = invisible-score/managed only, no escalation. The slug names an owned arena captcha gate.
    challenge_gate: str = ""


PROFILES: dict[str, VendorProfile] = {
    # reCAPTCHA v3 (docs): 0.0-1.0 score, 1.0 very likely human, default action threshold 0.5, token ~120s single-use.
    "recaptcha_v3": VendorProfile("recaptcha_v3", "score", 120, 0.5, scored=True, inverted=True),
    # Cloudflare Turnstile (docs): non-interactive managed pass/fail, token 300s, {success, action, cdata,
    # metadata.ephemeral_id}.
    "turnstile": VendorProfile("turnstile", "managed", 300, 0.5, scored=False, inverted=False),
    # hCaptcha (docs): pass/fail + an enterprise `score` (malicious likelihood, higher = worse) + score_reason.
    # It also runs a widget pre-check (POST checksiteconfig) that either passes or escalates to the image challenge
    # behind an hsw proof token — mode stays `score` (siteverify), the gate names the checksiteconfig escalation.
    "hcaptcha": VendorProfile(
        "hcaptcha", "score", 120, 0.5, scored=True, inverted=False, challenge_gate="image-select"
    ),
    # reCAPTCHA v2 (docs): invisible/checkbox pre-check that ESCALATES to a 3x3 image grid when risk is high; verify
    # returns {success, challenge_ts, hostname, error-codes}. Owned escalation gate: the image-select captcha.
    "recaptcha_v2": VendorProfile(
        "recaptcha_v2", "challenge", 120, 0.5, scored=False, inverted=False, challenge_gate="image-select"
    ),
    # Arkose FunCaptcha (docs): risk pre-check escalating to an interactive game; verify is pass/fail. Owned
    # escalation gate: the shape-select game (image-shapes).
    "arkose": VendorProfile(
        "arkose", "challenge", 300, 0.5, scored=False, inverted=False, challenge_gate="image-shapes"
    ),
    # GeeTest (docs): behavioural risk pre-check escalating to a slide/icon-order puzzle; verify is pass/fail. The
    # icon-order variant maps to the owned ordered image-select gate.
    "geetest": VendorProfile(
        "geetest", "challenge", 120, 0.5, scored=False, inverted=False, challenge_gate="image-select"
    ),
    # Proton CAPTCHA (docs): Proton's self-hosted privacy captcha — a proof-of-work challenge plus an interactive
    # puzzle, verify is pass/fail. PoW-first, so the escalation gate is the owned PoW challenge (not an image grid).
    "proton": VendorProfile("proton", "challenge", 300, 0.5, scored=False, inverted=False, challenge_gate="pow"),
    # --- Non-interactive PROOF-OF-WORK widgets: every visitor solves a PoW puzzle client-side; siteverify validates
    # the solution. Pure cost gates (no bot/human discrimination in the protocol itself) — the lab maps the coherence
    # verdict onto each family's documented response shape, which is the thesis: PoW is a cost gate, coherence convicts.
    # Friendly Captcha (docs): {success, errors[]} solution verify, non-interactive PoW.
    "friendly_captcha": VendorProfile("friendly_captcha", "managed", 300, 0.5, scored=False, inverted=False),
    # mCaptcha (docs): self-hosted PoW; verify returns {valid}.
    "mcaptcha": VendorProfile("mcaptcha", "managed", 300, 0.5, scored=False, inverted=False),
    # ALTCHA (docs): self-hosted GDPR-friendly PoW; verify returns {success, verified}.
    "altcha": VendorProfile("altcha", "managed", 300, 0.5, scored=False, inverted=False),
}

# challenge_gate slugs that are NOT /arena/captcha image kinds resolve to their own owned gate endpoint.
_GATE_URLS = {"pow": "/arena/challenge", "slider": "/arena/slider"}


def challenge_url(profile: VendorProfile) -> str:
    """The owned escalation-gate URL for a challenge-mode family — a PoW/slider gate has its own endpoint; every
    other slug is an /arena/captcha image kind (image-select, image-shapes, …)."""
    g = profile.challenge_gate
    return _GATE_URLS.get(g, f"/arena/captcha?kind={g}")


def vendor_score(profile: VendorProfile, kitsune_score: float) -> float:
    """Map Kitsune's coherence score (0-1, higher = more bot) onto the vendor's scale, clamped + 2dp."""
    s = 1.0 - kitsune_score if profile.inverted else kitsune_score
    return round(max(0.0, min(1.0, s)), 2)


def challenge_required(profile: VendorProfile, kitsune_score: float | None) -> bool:
    """The ladder decision for a challenge-mode family: escalate to the interactive gate when the invisible
    pre-check is suspicious (score >= threshold), OR when there is no session yet to judge (can't prove coherence
    -> escalate, matching a checkbox that always runs its risk check). Non-challenge families never escalate."""
    if not profile.challenge_gate:
        return False
    if kitsune_score is None:
        return True
    return kitsune_score >= profile.threshold


def shape_checksiteconfig(profile: VendorProfile, kitsune_score: float | None, sitekey: str) -> dict[str, object]:
    """hCaptcha's widget pre-check (POST checksiteconfig?...&sc=1&swa=1&spst=1) — vendor-neutral reproduction of
    the captured protocol. pass=True => passive pass, no visual challenge; otherwise escalate to the image
    challenge behind an `hsw` proof token (hCaptcha's proof-of-work), and name the owned escalation gate."""
    passed = kitsune_score is not None and kitsune_score < profile.threshold
    out: dict[str, object] = {"pass": passed, "sitekey": sitekey}
    if not passed:
        # the hsw (hCaptcha Signal Work) proof descriptor + the image-label-binary challenge type
        out["c"] = {"type": "hsw", "req": hashlib.sha256((sitekey or "hcaptcha").encode()).hexdigest()}
        out["request_type"] = "image_label_binary"
        out["challenge_url"] = challenge_url(profile)
    return out


def shape_siteverify(
    profile: VendorProfile, kitsune_score: float, action: str, challenge_ts: str, hostname: str, sid: str
) -> dict[str, object]:
    """Build the family-specific siteverify JSON from a verdict — the documented field shape, vendor-neutral."""
    passed = kitsune_score < profile.threshold  # coherent (not a bot) on Kitsune's scale
    # Non-interactive PoW widgets return their own minimal shapes (no challenge_ts/hostname) — the verdict maps onto
    # the family's documented pass/fail field. (The RED point stands: a PoW-solving bot still fails on coherence.)
    if profile.name == "friendly_captcha":
        return {"success": passed, "errors": [] if passed else ["solution_invalid"]}
    if profile.name == "mcaptcha":
        return {"valid": passed}
    if profile.name == "altcha":
        return {"success": passed, "verified": passed}
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
    elif profile.mode == "challenge":
        # reCAPTCHA v2 / Arkose verify shape: managed pass/fail. `passed` already folds in the arena solve tell —
        # a superhuman gate solve raises the session's bot score via the joined anomaly, so it fails here too.
        out["success"] = passed
        out["action"] = action
    return out
