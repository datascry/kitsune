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
* **Tor Browser / Mullvad Browser / RFP-Firefox** — resistFingerprinting blocks the canvas readback (a
  solid fill reads back uniform-white, tripping ``canvas_noise``) and forces UTC + a letterboxed window + 2
  cores. Identified by ``browser.rfp_browser`` (that conjunction). ``rfp_browser`` itself is an *environment*
  tell (corroborates, never convicts).

Both are legitimate human browsers, so when a session positively identifies as one of them those farbling /
blocked-readback artifacts are expected and dropped before scoring. A Chrome-claiming farbler with NO
``navigator.brave`` (an anti-detect tool) keeps them and still convicts; and a privacy-browser-faking bot is
still caught by its automation tells (webdriver / CDP), so this cannot help a bot escape.
"""

from __future__ import annotations

from .models import MISSING, Contradiction, Layer, Session

# Canvas/audio readback artifacts that a privacy browser produces BY DESIGN (Brave farbling, RFP blocking).
_PRIVACY_FARBLING = frozenset({"br.canvas_noise", "br.audio_noise"})


def _privacy_browser(session: Session) -> str | None:
    """Name the privacy browser the session positively identifies as, or ``None``."""
    if session.value(Layer.browser, "is_brave") is True:
        return "Brave"
    if session.value(Layer.browser, "rfp_browser") is True:
        return "a resistFingerprinting browser (Tor / Mullvad / RFP-Firefox)"
    return None


def not_applicable(rule_id: str, session: Session) -> str | None:
    """Return a reason the rule does NOT apply to this session's browser, or ``None`` if it applies."""
    if rule_id in _PRIVACY_FARBLING:
        who = _privacy_browser(session)
        if who is not None:
            return f"{who} farbles/blocks the canvas/audio readback by design — expected, not a bot signature"
    return None


def filter_applicable(contradictions: list[Contradiction], session: Session) -> list[Contradiction]:
    """Drop the contradictions that are not applicable to this session's identified browser."""
    if session.value(Layer.browser, "is_brave") is MISSING and (session.value(Layer.browser, "rfp_browser") is MISSING):
        return contradictions  # fast path: no privacy-browser context to apply
    return [c for c in contradictions if not_applicable(c.rule_id, session) is None]
