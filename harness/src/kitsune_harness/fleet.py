# harness/fleet — coordination detection: cluster sessions by a low-level fingerprint signature.
# The durable signal: per-session anti-detect can't hide that a fleet shares one TLS/hardware identity.

"""Fleet / coordination detection.

A single session can spoof its fingerprint perfectly (Camoufox proves it). But a *fleet* of bots
shares a signature **below the spoofing layer**. Empirically: 3 Camoufox instances randomize their
JS-visible fingerprint per launch (hardware 8/32/8, platform Windows/macOS) — yet their **TLS JA4 is
identical**, because the handshake is the engine's and anti-detect tools spoof JS, not the TLS stack.
So the fleet key must be JA4 alone; JS traits like hardwareConcurrency are exactly what the tool
randomizes to look diverse. Real same-browser users share JA4 too, so a JA4 cluster is a fleet
*candidate* — combined with volume/timing/IP it is the bots/DDoS signal no fingerprint spoof escapes.
"""

from __future__ import annotations

from collections import defaultdict

from kitsune_detector.models import MISSING, Layer, Session


# JA4 only: the TLS engine identity, below the JS layer the anti-detect tools randomize.
def fleet_signature(session: Session) -> str:
    """A stable cross-session identity: the JA4 cipher-suite prefix (JA4_a + JA4_b). Anti-detect
    browsers (Camoufox) randomize JA4_c (extensions/sig-algs) per launch, so the full JA4 is not
    fleet-stable — but the cipher suites are the engine's and do not randomize."""
    value = session.value(Layer.network, "ja4")
    prefix = "?" if value is MISSING else "_".join(str(value).split("_")[:2])
    return f"ja4={prefix}"


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
        return "\n".join([*lines, "- (no shared signatures — all sessions are distinct)"]) + "\n"
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
