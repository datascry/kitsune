# detector/applicability — per-browser rule applicability: a tell expected for the identified browser is N/A.
# Drops "expected for this browser" contradictions before scoring so a real browser is not convicted on them.

"""Per-browser applicability (the server-side analog of the live page's ``predict.notApplicable``).

A detection that is *meaningless for the browser the session actually is* must not count against it — that
is what keeps real, legitimate browsers off the bot pile. The load-bearing class is the **privacy browser**,
whose anti-fingerprinting defenses look like the artifacts an anti-detect tool injects but are a feature a
HUMAN turned on:

* **Brave** — its default Shields farble the canvas and audio readback, so a real Brave user trips
  ``canvas_noise`` + ``audio_noise``. Identified by the definitive ``navigator.brave`` global
  (``browser.is_brave``).
* **Tor Browser / Mullvad Browser / RFP-Firefox** — resistFingerprinting perturbs the canvas readback
  (tripping ``canvas_noise`` + ``canvas_geometry_noise`` + ``canvas_worker_vs_main``) and forces UTC + a
  letterboxed window + a "Mozilla" WebGL vendor/renderer. Identified by ``browser.rfp_browser`` (that
  conjunction; modern Tor/Mullvad no longer clamp cores to 2, so the WebGL tell — not cores — is the reliable
  third leg). ``rfp_browser`` itself is an *environment* tell (corroborates, never convicts).

Both are legitimate human browsers, so when a session positively identifies as one of them those farbling /
blocked-readback artifacts are expected and dropped before scoring. A Chrome-claiming farbler with NO
``navigator.brave`` (an anti-detect tool) keeps them and still convicts; and a privacy-browser-faking bot is
still caught by its automation tells (webdriver / CDP), so this cannot help a bot escape.
"""

from __future__ import annotations

from .models import MISSING, Contradiction, Layer, Session

# Canvas/audio readback artifacts that a privacy browser produces BY DESIGN (Brave farbling, RFP blocking).
# canvas_noise = perturbed/blocked 2D readback; audio_noise = per-render audio perturbation; readback_noise
# = getChannelData vs copyFromChannel divergence. v0.74.26 (GROUNDED on a real Mullvad Browser, see
# corpus/calibration/privacy/mullvad.json): RFP's canvas randomization ALSO trips canvas_geometry_noise
# (per-call DOMRect/getClientRects perturbation) and canvas_worker_vs_main (main and Worker OffscreenCanvas
# get DIFFERENT per-call noise, so their pixels diverge) — the SAME privacy-feature footprint, both convicting
# (artifact / coherence) and both FP on a real Tor/Mullvad. Stock (non-RFP) Firefox trips NONE of the five
# (corpus/calibration/headful/firefox.json), so these are RFP-on artifacts, not a Gecko baseline. A genuine
# Brave/Tor/Mullvad/RFP-Firefox user must not be convicted on any of them. (Camoufox, an anti-detect TOOL,
# sets neither navigator.brave nor the RFP conjunction, so it is not exempted and stays caught.)
_PRIVACY_FARBLING = frozenset(
    {
        "br.canvas_noise",
        "br.audio_noise",
        "br.readback_noise",
        "br.canvas_geometry_noise",
        "br.canvas_worker_vs_main",
    }
)

# The mouse-biomech behavioral FLOORS — calibrated on mouse-on-desktop corpora (Balabit, SapiMouse). On a
# REAL mobile device the collector still derives them from touch-driven pointermove events, but a finger
# swipe is near-straight, constant-velocity, has no hardware coalescing, and yields a short power-law
# sample — so these floors false-positive on a real phone (capped at suspicious by the conviction gate, but
# still a precision hit). They are dropped for a session that GENUINELY identifies as mobile
# (browser.is_mobile: a mobile UA token AND maxTouchPoints>0). trace_replay stays active (device-agnostic,
# convicting), as does the keystroke floor (keyboard, not mouse). G10 — mobile-vs-desktop analysis 2026-06-23.
_MOBILE_BIOMECH_NA = frozenset(
    {
        "bh.input_entropy_floor",
        "bh.power_law_violation",
        "bh.path_too_straight",
        "bh.uniform_velocity",
        "bh.synthetic_no_coalesced",
    }
)


def _privacy_browser(session: Session) -> str | None:
    """Name the privacy browser the session GENUINELY identifies as, or ``None``.

    Genuineness matters: the farbling N/A is only granted to a real privacy browser, never to a bot that
    fakes the identity to get its farbling excused. Brave must have a native ``navigator.brave``
    (``is_brave`` and not ``brave_spoofed``); RFP is Firefox-only, so the conjunction is honored only on a
    Gecko engine (a Chromium session claiming RFP letterboxing/UTC/"Mozilla"-WebGL is itself incoherent).
    """
    if session.value(Layer.browser, "is_brave") is True and (session.value(Layer.browser, "brave_spoofed") is not True):
        return "Brave"
    if session.value(Layer.browser, "rfp_browser") is True and session.value(Layer.browser, "ua_engine") == "firefox":
        return "a resistFingerprinting browser (Tor / Mullvad / RFP-Firefox)"
    return None


def not_applicable(rule_id: str, session: Session) -> str | None:
    """Return a reason the rule does NOT apply to this session's browser, or ``None`` if it applies."""
    if rule_id in _PRIVACY_FARBLING:
        who = _privacy_browser(session)
        if who is not None:
            return f"{who} farbles/blocks the canvas/audio readback by design — expected, not a bot signature"
    # Firefox (and every Gecko browser: Tor, Mullvad, Camoufox) GENERALISES the WebGL UNMASKED_RENDERER
    # string by default — "<gpu>, or similar" / "llvmpipe, or similar" — as a fingerprinting-resistance
    # feature, NOT a spoof placeholder. A live headful Firefox 137 reports "llvmpipe, or similar" and trips
    # br.webgl_renderer_artifact (the ", or similar" arm), which is a convicting `artifact` rule — so the
    # rule false-fires on every real Firefox. The artifact pattern stays valid for Chromium (which never
    # emits that format), so the rule is dropped only for the Gecko engine that legitimately produces it.
    if rule_id == "br.webgl_renderer_artifact" and session.value(Layer.browser, "ua_engine") == "firefox":
        return "Firefox generalises the WebGL renderer string ('…, or similar') by design — a privacy feature"
    if rule_id in _MOBILE_BIOMECH_NA and session.value(Layer.browser, "is_mobile") is True:
        return "mouse-biomechanics floors do not apply to a touch device — calibrated on mouse-on-desktop only"
    return None


def filter_applicable(contradictions: list[Contradiction], session: Session) -> list[Contradiction]:
    """Drop the contradictions that are not applicable to this session's identified browser."""
    no_brave = session.value(Layer.browser, "is_brave") is MISSING
    no_rfp = session.value(Layer.browser, "rfp_browser") is MISSING
    no_mobile = session.value(Layer.browser, "is_mobile") is not True
    if no_brave and no_rfp and no_mobile and session.value(Layer.browser, "ua_engine") != "firefox":
        return contradictions  # fast path: no privacy-browser / Gecko / mobile context to apply
    return [c for c in contradictions if not_applicable(c.rule_id, session) is None]
