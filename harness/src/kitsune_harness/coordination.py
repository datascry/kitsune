# harness/coordination — grade a JA4 cluster into a fleet verdict via the TLS-vs-JS paradox.
# A real same-build cluster shares JS traits too; an anti-detect fleet randomizes JS yet shares one JA4.

"""Coordination scoring.

[[fleet]] groups sessions by JA4 (the TLS-engine identity below the JS spoofing layer). But a JA4
cluster alone is only a *candidate* — millions of real users run the same Chrome build and share a
JA4. The discriminator is a paradox an anti-detect fleet cannot avoid:

    A genuine same-browser cohort that shares one JA4 also shares its JS-visible identity
    (hardwareConcurrency, platform, plugin set) — they are literally the same build on similar
    machines. An anti-detect fleet deliberately *randomizes* those JS traits per instance to look
    like distinct users — but it cannot randomize the TLS handshake, which is the engine's.

So **identical TLS + divergent JS within one cluster** is the signal: it is the shape only a
spoofing fleet produces. Real diversity comes with diverse JA4; real JA4-sharing comes with shared
JS. The two diverging at once is the tell. This is the durable bots/DDoS signal — it survives any
per-session fingerprint spoof because it is a property of the *cluster*, not the instance.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from kitsune_detector.models import MISSING, Layer, Session

# JS-visible traits an anti-detect tool randomizes per instance to fake diversity. A real
# same-JA4 cohort is homogeneous here; divergence across a JA4 cluster is the paradox.
_SPOOFABLE_TRAITS: list[tuple[Layer, str]] = [
    (Layer.browser, "nav_platform_os"),
    (Layer.browser, "ua_platform"),
    (Layer.browser, "hardware_concurrency"),
    (Layer.browser, "plugins_count"),
    (Layer.browser, "device_memory"),
]

_BASE_CANDIDATE = 0.30  # a shared-JA4 cluster, on its own (humans do this too)
_PARADOX_BONUS = 0.55  # identical TLS + divergent JS — the spoofing-fleet shape
_PER_MEMBER = 0.05  # each member beyond the second, capped
_MAX_MEMBER_BONUS = 0.15


@dataclass(frozen=True)
class FleetVerdict:
    """A graded coordination verdict for one JA4 cluster."""

    ja4: str
    members: list[str]
    diverged_traits: dict[str, int]  # trait kind -> distinct value count (only those > 1)
    score: float
    label: str  # "fleet" | "candidate" | "benign"
    evidence: list[str] = field(default_factory=list)


def _ja4(session: Session) -> str | None:
    v = session.value(Layer.network, "ja4")
    return None if v is MISSING else str(v)


def _diverged_traits(sessions: list[Session]) -> dict[str, int]:
    """For each spoofable trait, the count of distinct non-missing values across the cluster."""
    out: dict[str, int] = {}
    for layer, kind in _SPOOFABLE_TRAITS:
        values = {session.value(layer, kind) for session in sessions}
        values.discard(MISSING)
        if len(values) > 1:
            out[kind] = len(values)
    return out


def score_cluster(ja4: str, members: list[tuple[str, Session]]) -> FleetVerdict:
    """Grade one JA4 cluster (>= 2 sessions sharing ``ja4``) into a FleetVerdict."""
    names = sorted(n for n, _ in members)
    sessions = [s for _, s in members]
    diverged = _diverged_traits(sessions)

    score = _BASE_CANDIDATE
    evidence = [f"{len(names)} sessions share JA4 `{ja4}`"]
    score += min((len(names) - 2) * _PER_MEMBER, _MAX_MEMBER_BONUS)

    if diverged:
        score += _PARADOX_BONUS
        detail = ", ".join(f"{k}×{v}" for k, v in sorted(diverged.items()))
        evidence.append(f"TLS identical but JS divergent across members: {detail}")
    else:
        evidence.append("JS traits homogeneous across members — consistent with a real cohort")

    score = max(0.0, min(1.0, score))
    label = "fleet" if score >= 0.60 else "candidate" if score >= 0.30 else "benign"
    return FleetVerdict(
        ja4=ja4, members=names, diverged_traits=diverged, score=round(score, 3),
        label=label, evidence=evidence,
    )


def score_corpus(corpus: list[tuple[str, Session]]) -> list[FleetVerdict]:
    """Cluster a corpus by JA4 and grade every cluster of size > 1, strongest first."""
    clusters: dict[str, list[tuple[str, Session]]] = {}
    for name, session in corpus:
        ja4 = _ja4(session)
        if ja4 is None:
            continue
        clusters.setdefault(ja4, []).append((name, session))
    verdicts = [score_cluster(ja4, members) for ja4, members in clusters.items() if len(members) > 1]
    return sorted(verdicts, key=lambda v: -v.score)


def render_coordination(corpus: list[tuple[str, Session]]) -> str:
    """Render graded fleet verdicts as markdown."""
    verdicts = score_corpus(corpus)
    lines = [f"## Coordination — {len(verdicts)} graded cluster(s) across {len(corpus)} sessions", ""]
    if not verdicts:
        return "\n".join(lines + ["- (no JA4 cluster of size > 1)"]) + "\n"
    for v in verdicts:
        lines.append(f"### `{v.label}` — score **{v.score:.2f}** · {len(v.members)} sessions")
        lines.append(f"- members: {', '.join(v.members)}")
        for e in v.evidence:
            lines.append(f"- {e}")
        lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI
    import sys

    from .corpus import load_corpus

    argv = sys.argv[1:] if argv is None else argv
    directory = argv[0] if argv else "corpus/fleet"
    print(render_coordination(load_corpus(directory)), end="")


if __name__ == "__main__":  # pragma: no cover
    main()
