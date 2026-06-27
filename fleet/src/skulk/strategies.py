# fleet/skulk/strategies — the modular fleet shapes: cloned / randomizer / trace-replay / fuzzy.
# Each maps an attacker's coordination strategy to N FleetMembers; the registry makes them pluggable.

"""Fleet strategies — the red-team menu, each grounding a blue coordination signal.

Every strategy is a deterministic generator (seeded → reproducible) of N :class:`FleetMember`. They model the
two escape routes a coordinated fleet has and their evolution:

  * ``cloned``       — one pinned anti-detect profile across distinct IPs (the BotBrowser/clone class). The
                       high-entropy ``fp_hash`` is byte-identical fleet-wide → an exact fp-collision a detector
                       convicts (the cloned-profile-behind-proxies shape).
  * ``randomizer``   — per-instance COHERENT fingerprints sharing one JA4 across distinct IPs (the Multilogin/
                       GoLogin multi-accounting class). The TLS/JS paradox; convicts only when corroborated
                       (automation tell or IP-reputation flag), else a real diverse cohort produces this shape.
  * ``trace-replay`` — one canned "humanised" pointer trace replayed across distinct IPs (engagement/review-
                       farm class). The ``trace_hash`` is identical fleet-wide → an unambiguous trace-collision.
  * ``fuzzy``        — the EVOLVED adversary: jitter the fingerprint AND the trace per instance so NOTHING is
                       byte-identical. It defeats exact-hash collision (caps a per-session-saturated scorer at
                       *candidate*) — the frontier that needs template-SIMILARITY clustering, not exact match.

To add a strategy: subclass / duck-type :class:`~skulk.strategy.Strategy` and ``register`` it.
"""

from __future__ import annotations

import hashlib
import random

from .model import FleetMember
from .strategy import register


def _h(*parts: object) -> str:
    """A stable 16-hex digest of the parts — stands in for a high-entropy fp_hash / trace_hash."""
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def _ip(seed: int, i: int) -> str:
    """A distinct source IP per node (the in-sandbox analog of one proxy egress per fleet member)."""
    return f"10.77.{seed % 254 + 1}.{i + 1}"


def _ja4(seed: int) -> str:
    """One shared JA4 (the TLS engine the whole fleet runs — below the JS spoofing layer)."""
    return "t13d1516h2_" + _h("ja4", seed)[:12] + "_" + _h("ext", seed)[:12]


@register
class ClonedProfile:
    name = "cloned"
    summary = "One pinned anti-detect profile cloned across N distinct IPs (BotBrowser class) — exact fp-collision."

    def members(self, n: int, seed: int) -> list[FleetMember]:
        ja4, fp = _ja4(seed), _h("clonedfp", seed)
        return [
            FleetMember(
                f"cloned-{i}", ja4, _ip(seed, i), fp_hash=fp, hardware_concurrency=8, platform="Win32", automation=True
            )
            for i in range(n)
        ]


@register
class CoherentRandomizer:
    name = "randomizer"
    summary = "Coherent per-instance fingerprints, one JA4, distinct IPs (Multilogin class) — the TLS/JS paradox."

    def members(self, n: int, seed: int) -> list[FleetMember]:
        ja4 = _ja4(seed)
        rng = random.Random(seed)
        plats = ["Win32", "MacIntel", "Linux x86_64"]
        return [
            FleetMember(
                f"rand-{i}",
                ja4,
                _ip(seed, i),
                fp_hash=_h("randfp", seed, i),
                hardware_concurrency=rng.choice([4, 8, 12, 16]),
                platform=rng.choice(plats),
                automation=False,
            )
            for i in range(n)
        ]


@register
class TraceReplay:
    name = "trace-replay"
    summary = (
        "One canned pointer trace replayed across N distinct IPs (engagement-farm class) — unambiguous trace-collision."
    )

    def members(self, n: int, seed: int) -> list[FleetMember]:
        ja4, trace = _ja4(seed), _h("trace", seed)
        return [
            FleetMember(f"trace-{i}", ja4, _ip(seed, i), fp_hash=_h("tfp", seed, i), trace_hash=trace) for i in range(n)
        ]


@register
class Fuzzy:
    name = "fuzzy"
    summary = "EVOLVED: jittered fingerprint + trace per instance — evades exact-hash (the similarity frontier)."

    def members(self, n: int, seed: int) -> list[FleetMember]:
        ja4 = _ja4(seed)
        # Every node's fp_hash and trace_hash is DISTINCT (jittered) — no two are byte-identical, so an
        # exact-match collision detector finds nothing and caps the cluster at `candidate`. The members are
        # still one fleet (shared JA4, lockstep, one IP block); only SIMILARITY clustering catches them.
        return [
            FleetMember(
                f"fuzzy-{i}",
                ja4,
                _ip(seed, i),
                fp_hash=_h("fuzzyfp", seed, i),
                trace_hash=_h("fuzzytrace", seed, i),
                hardware_concurrency=8,
                platform="Win32",
                automation=False,
            )
            for i in range(n)
        ]
