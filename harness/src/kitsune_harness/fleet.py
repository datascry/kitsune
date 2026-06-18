# harness/fleet — coordination detection: cluster sessions by a low-level fingerprint signature.
# The durable signal: per-session anti-detect can't hide that a fleet shares one TLS/hardware identity.

"""Fleet / coordination detection.

A single session can spoof its fingerprint perfectly (Camoufox proves it). But a *fleet* of bots
shares a signature below the spoofing layer — the same TLS (JA4) and hardware profile across many
"users". Real humans are diverse; a coordinated fleet is homogeneous. This clusters the corpus by a
stable signature and flags groups of size > 1 — the bots/DDoS frontier no fingerprint spoof addresses.
"""

from __future__ import annotations

from collections import defaultdict

from kitsune_detector.models import MISSING, Layer, Session

# Signals chosen because they sit *below* the JS/engine spoofing layer (JA4 = TLS handshake) or are
# stable hardware traits a fleet shares.
_SIGNATURE = [
    (Layer.network, "ja4"),
    (Layer.browser, "hardware_concurrency"),
]


def fleet_signature(session: Session) -> str:
    """A stable cross-session identity: JA4 + hardware profile."""
    parts = []
    for layer, kind in _SIGNATURE:
        value = session.value(layer, kind)
        parts.append(f"{kind}={'?' if value is MISSING else value}")
    return " | ".join(parts)


def detect_fleets(corpus: list[tuple[str, Session]]) -> dict[str, list[str]]:
    """Group session names by signature; return only clusters of size > 1 (candidate fleets)."""
    groups: dict[str, list[str]] = defaultdict(list)
    for name, session in corpus:
        groups[fleet_signature(session)].append(name)
    return {sig: sorted(names) for sig, names in groups.items() if len(names) > 1}


def render_fleets(corpus: list[tuple[str, Session]]) -> str:
    fleets = detect_fleets(corpus)
    lines = [f"## Fleets — {len(fleets)} coordinated cluster(s) across {len(corpus)} sessions", ""]
    if not fleets:
        return "\n".join(lines + ["- (no shared signatures — all sessions are distinct)"]) + "\n"
    for sig, members in sorted(fleets.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"- **{len(members)} sessions share** `{sig}`: {', '.join(members)}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI
    import sys

    from .corpus import DEFAULT_CORPUS, load_corpus

    argv = sys.argv[1:] if argv is None else argv
    directory = argv[0] if argv else DEFAULT_CORPUS
    print(render_fleets(load_corpus(directory)), end="")


if __name__ == "__main__":  # pragma: no cover
    main()
