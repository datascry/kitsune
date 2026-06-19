# detector/applicability — per-browser rule applicability: a tell expected for the identified browser is N/A.
# Drops "expected for this browser" contradictions before scoring so a real browser is not convicted on them.

"""Per-browser applicability (the server-side analog of the live page's ``predict.notApplicable``).

A detection that is *meaningless for the browser the session actually is* must not count against it — that
is what keeps real, legitimate browsers off the bot pile. The load-bearing case is **Brave**: its default
Shields farble the canvas and audio readback, so a real Brave user trips ``canvas_noise`` + ``audio_noise``
(both *artifact* = convicting) and would noisy-or to ``bot``. Brave is a legitimate human browser (~70M
users), so when the session positively identifies as Brave (the definitive ``navigator.brave`` global,
emitted as ``browser.is_brave``) those farbling artifacts are expected and dropped. A Chrome-claiming farbler
with no ``navigator.brave`` (an anti-detect tool) keeps them and still convicts; and a Brave-faking bot is
still caught by its automation tells (webdriver / CDP), so this cannot help a bot escape.
"""

from __future__ import annotations

from .models import MISSING, Contradiction, Layer, Session

# Tells that are a BY-DESIGN feature of a specific browser, keyed by the context signal that identifies it.
_BRAVE_FARBLING = frozenset({"br.canvas_noise", "br.audio_noise"})


def _is_brave(session: Session) -> bool:
    return session.value(Layer.browser, "is_brave") is True


def not_applicable(rule_id: str, session: Session) -> str | None:
    """Return a reason the rule does NOT apply to this session's browser, or ``None`` if it applies."""
    if rule_id in _BRAVE_FARBLING and _is_brave(session):
        return "Brave farbles canvas/audio readback by design (Shields) — expected, not a bot signature"
    return None


def filter_applicable(contradictions: list[Contradiction], session: Session) -> list[Contradiction]:
    """Drop the contradictions that are not applicable to this session's identified browser."""
    if session.value(Layer.browser, "is_brave") is MISSING:
        return contradictions  # fast path: no per-browser context to apply
    return [c for c in contradictions if not_applicable(c.rule_id, session) is None]
