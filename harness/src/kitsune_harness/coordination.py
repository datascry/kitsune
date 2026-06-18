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
_LOCKSTEP_WINDOW_S = 120.0  # sessions sharing a JA4 all arriving within this window are synchronized
_LOCKSTEP_BONUS = 0.12  # tightens confidence; kept < the fleet threshold so the JS paradox stays primary
# JA4_c (extensions + signature algorithms) divergence under a shared cipher-suite prefix. JA4 *sorts*
# extensions specifically to be robust to Chrome's order shuffling, so a varying JA4_c means the actual
# extension/sig-alg set is being manipulated per launch — an anti-detect TLS tell (Camoufox does this).
_JA4C_BONUS = 0.30
# A *confirmed* spoofing fleet (paradox or JA4_c) that is also spread across many distinct source IPs is
# the residential-proxy botnet pattern: the IP diversity is there to look like distinct users and defeat
# IP rate-limiting / datacenter-ASN rules, but the shared engine identity binds them. A modest escalation
# (IP diversity alone is the null hypothesis — many real users share a JA4 prefix — so it only adds once a
# spoofing tell is already present).
_PROXY_FLEET_BONUS = 0.10
# Diverse observed (proxy) IPs but ONE shared WebRTC-leaked real IP: proxies fronting a single origin.
# Very hard to explain innocently — a strong same-origin signal.
_SHARED_ORIGIN_BONUS = 0.30


@dataclass(frozen=True)
class FleetVerdict:
    """A graded coordination verdict for one JA4-prefix cluster."""

    ja4: str  # the shared JA4 prefix (JA4_a + JA4_b: TLS version/ALPN + cipher-suite hash)
    members: list[str]
    diverged_traits: dict[str, int]  # trait kind -> distinct value count (only those > 1)
    score: float
    label: str  # "fleet" | "candidate" | "benign"
    span_seconds: float | None = None  # first_seen spread across members (None if < 2 timestamps)
    ja4c_divergent: bool = False  # members share the cipher prefix but differ in extensions/sig-algs
    distinct_observed_ips: int = 0  # distinct source IPs across the cluster (proxy spread)
    shared_real_ip: str | None = None  # one WebRTC-leaked real IP behind diverse proxy IPs (same origin)
    evidence: list[str] = field(default_factory=list)


def _ja4(session: Session) -> str | None:
    v = session.value(Layer.network, "ja4")
    return None if v is MISSING else str(v)


def _ja4_prefix(ja4: str) -> str:
    """JA4_a + JA4_b (the engine's TLS version/ALPN + cipher-suite identity), dropping the
    randomizable JA4_c (extensions/sig-algs). For ``t13d1717h2_5b57614c22b0_3cbfd9..`` →
    ``t13d1717h2_5b57614c22b0``. Robust to per-launch extension randomization."""
    return "_".join(ja4.split("_")[:2])


def _first_seen_span(sessions: list[Session]) -> float | None:
    """Seconds between the earliest and latest first_seen across the cluster (None if < 2)."""
    stamps = sorted(s.first_seen for s in sessions)
    if len(stamps) < 2:
        return None
    return (stamps[-1] - stamps[0]).total_seconds()


def _diverged_traits(sessions: list[Session]) -> dict[str, int]:
    """For each spoofable trait, the count of distinct non-missing values across the cluster."""
    out: dict[str, int] = {}
    for layer, kind in _SPOOFABLE_TRAITS:
        values = {session.value(layer, kind) for session in sessions}
        values.discard(MISSING)
        if len(values) > 1:
            out[kind] = len(values)
    return out


def _distinct_values(sessions: list[Session], layer: Layer, kind: str) -> set[object]:
    """The set of distinct non-missing values for one signal across the cluster."""
    vals = {session.value(layer, kind) for session in sessions}
    vals.discard(MISSING)
    return vals


def score_cluster(prefix: str, members: list[tuple[str, Session]]) -> FleetVerdict:
    """Grade one JA4-prefix cluster (>= 2 sessions sharing the cipher-suite ``prefix``)."""
    names = sorted(n for n, _ in members)
    sessions = [s for _, s in members]
    diverged = _diverged_traits(sessions)
    full_ja4s = {_ja4(s) for s in sessions}
    full_ja4s.discard(None)
    ja4c_divergent = len(full_ja4s) > 1

    score = _BASE_CANDIDATE
    evidence = [f"{len(names)} sessions share JA4 cipher prefix `{prefix}`"]
    score += min((len(names) - 2) * _PER_MEMBER, _MAX_MEMBER_BONUS)

    if diverged:
        score += _PARADOX_BONUS
        detail = ", ".join(f"{k} x{v}" for k, v in sorted(diverged.items()))
        evidence.append(f"cipher suites identical but JS divergent across members: {detail}")
    else:
        evidence.append("JS traits homogeneous across members — consistent with a real cohort")

    if ja4c_divergent:
        score += _JA4C_BONUS
        evidence.append(
            f"cipher suites identical but JA4 extensions/sig-algs divergent "
            f"({len(full_ja4s)} variants) — per-launch TLS randomization"
        )

    span = _first_seen_span(sessions)
    if span is not None and span <= _LOCKSTEP_WINDOW_S:
        score += _LOCKSTEP_BONUS
        evidence.append(f"timing lockstep: all members arrived within {span:.0f}s")
    elif span is not None:
        evidence.append(f"arrivals spread over {span:.0f}s — no lockstep")

    # IP topology: residential-proxy spread + same-origin-behind-proxies (the bots/DDoS frontier).
    observed = _distinct_values(sessions, Layer.network, "observed_ip")
    webrtc = _distinct_values(sessions, Layer.browser, "webrtc_public_ip")
    distinct_observed = len(observed)
    shared_real_ip: str | None = None
    if (diverged or ja4c_divergent) and distinct_observed > 1:
        score += _PROXY_FLEET_BONUS
        evidence.append(
            f"distributed across {distinct_observed} distinct source IPs — residential-proxy fleet "
            f"pattern (IP diversity masks one shared engine, defeating IP/ASN rules)"
        )
    if distinct_observed > 1 and len(webrtc) == 1:
        shared_real_ip = str(next(iter(webrtc)))
        score += _SHARED_ORIGIN_BONUS
        evidence.append(
            f"{distinct_observed} proxy IPs front one real IP `{shared_real_ip}` (WebRTC) — same-origin fleet"
        )

    score = max(0.0, min(1.0, score))
    label = "fleet" if score >= 0.60 else "candidate" if score >= 0.30 else "benign"
    return FleetVerdict(
        ja4=prefix,
        members=names,
        diverged_traits=diverged,
        score=round(score, 3),
        label=label,
        span_seconds=span,
        ja4c_divergent=ja4c_divergent,
        distinct_observed_ips=distinct_observed,
        shared_real_ip=shared_real_ip,
        evidence=evidence,
    )


def score_corpus(corpus: list[tuple[str, Session]]) -> list[FleetVerdict]:
    """Cluster by JA4 *prefix* (cipher-suite identity) and grade clusters of size > 1, strongest first."""
    clusters: dict[str, list[tuple[str, Session]]] = {}
    for name, session in corpus:
        ja4 = _ja4(session)
        if ja4 is None:
            continue
        clusters.setdefault(_ja4_prefix(ja4), []).append((name, session))
    verdicts = [score_cluster(p, members) for p, members in clusters.items() if len(members) > 1]
    return sorted(verdicts, key=lambda v: -v.score)


def render_coordination(corpus: list[tuple[str, Session]]) -> str:
    """Render graded fleet verdicts as markdown."""
    verdicts = score_corpus(corpus)
    lines = [f"## Coordination — {len(verdicts)} graded cluster(s) across {len(corpus)} sessions", ""]
    if not verdicts:
        return "\n".join([*lines, "- (no JA4 cluster of size > 1)"]) + "\n"
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
